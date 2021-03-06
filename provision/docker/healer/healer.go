// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package healer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tsuru/config"
	"github.com/tsuru/docker-cluster/cluster"
	"github.com/tsuru/tsuru/db"
	"github.com/tsuru/tsuru/db/storage"
	"github.com/tsuru/tsuru/event"
	"github.com/tsuru/tsuru/provision/docker/container"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	consecutiveHealingsTimeframe        = 5 * time.Minute
	consecutiveHealingsLimitInTimeframe = 3
)

type HealingEvent struct {
	ID               interface{} `bson:"_id"`
	StartTime        time.Time
	EndTime          time.Time
	Action           string
	Reason           string
	Extra            interface{}
	FailingNode      cluster.Node
	CreatedNode      cluster.Node
	FailingContainer container.Container
	CreatedContainer container.Container
	Successful       bool
	Error            string
}

func init() {
	event.SetThrottling(event.ThrottlingSpec{
		TargetType: event.TargetTypeContainer,
		KindName:   "healer",
		Time:       consecutiveHealingsTimeframe,
		Max:        consecutiveHealingsLimitInTimeframe,
	})
	event.SetThrottling(event.ThrottlingSpec{
		TargetType: event.TargetTypeNode,
		KindName:   "healer",
		Time:       consecutiveHealingsTimeframe,
		Max:        consecutiveHealingsLimitInTimeframe,
	})
}

func toHealingEvt(evt *event.Event) (HealingEvent, error) {
	healingEvt := HealingEvent{
		ID:         evt.UniqueID,
		StartTime:  evt.StartTime,
		EndTime:    evt.EndTime,
		Action:     fmt.Sprintf("%s-healing", evt.Target.Type),
		Successful: evt.Error == "",
		Error:      evt.Error,
	}
	switch evt.Target.Type {
	case event.TargetTypeContainer:
		err := evt.StartData(&healingEvt.FailingContainer)
		if err != nil {
			return healingEvt, err
		}
		err = evt.EndData(&healingEvt.CreatedContainer)
		if err != nil {
			return healingEvt, err
		}
	case event.TargetTypeNode:
		var data nodeHealerCustomData
		err := evt.StartData(&data)
		if err != nil {
			return healingEvt, err
		}
		if data.LastCheck != nil {
			healingEvt.Extra = data.LastCheck
		}
		healingEvt.Reason = data.Reason
		if data.Node != nil {
			healingEvt.FailingNode = *data.Node
		}
		var createdNode cluster.Node
		err = evt.EndData(&createdNode)
		if err != nil {
			return healingEvt, err
		}
		healingEvt.CreatedNode = createdNode
	}

	return healingEvt, nil
}

func ListHealingHistory(filter string) ([]HealingEvent, error) {
	evtFilter := event.Filter{
		KindName: "healer",
		KindType: event.KindTypeInternal,
	}
	if filter != "" {
		t, err := event.GetTargetType(filter)
		if err == nil {
			evtFilter.Target = event.Target{Type: t}
		}
	}
	evts, err := event.List(&evtFilter)
	if err != nil {
		return nil, err
	}
	healingEvts := make([]HealingEvent, len(evts))
	for i := range evts {
		healingEvts[i], err = toHealingEvt(&evts[i])
		if err != nil {
			return nil, err
		}
	}
	return healingEvts, nil
}

func oldHealingCollection() (*storage.Collection, error) {
	name, _ := config.GetString("docker:healing:events_collection")
	if name == "" {
		name = "healing_events"
	}
	conn, err := db.Conn()
	if err != nil {
		return nil, err
	}
	return conn.Collection(name), nil
}

func healingEventToEvent(data *HealingEvent) error {
	var evt event.Event
	evt.UniqueID = data.ID.(bson.ObjectId)
	var startOpts, endOpts interface{}
	switch data.Action {
	case "node-healing":
		evt.Target = event.Target{Type: event.TargetTypeNode, Value: data.FailingNode.Address}
		var lastCheck *nodeChecks
		if data.Extra != nil {
			checkRaw, err := json.Marshal(data.Extra)
			if err == nil {
				json.Unmarshal(checkRaw, &lastCheck)
			}
		}
		startOpts = nodeHealerCustomData{
			Node:      &data.FailingNode,
			Reason:    data.Reason,
			LastCheck: lastCheck,
		}
		endOpts = data.CreatedNode
	case "container-healing":
		evt.Target = event.Target{Type: event.TargetTypeContainer, Value: data.FailingContainer.ID}
		startOpts = data.FailingContainer
		endOpts = data.CreatedContainer
	default:
		return fmt.Errorf("invalid action %q", data.Action)
	}
	evt.Owner = event.Owner{Type: event.OwnerTypeInternal}
	evt.Kind = event.Kind{Type: event.KindTypeInternal, Name: "healer"}
	evt.StartTime = data.StartTime
	evt.EndTime = data.EndTime
	evt.Error = data.Error
	err := evt.RawInsert(startOpts, nil, endOpts)
	if mgo.IsDup(err) {
		return nil
	}
	return err
}

func MigrateHealingToEvents() error {
	coll, err := oldHealingCollection()
	if err != nil {
		return err
	}
	defer coll.Close()
	coll.Find(nil).Iter()
	iter := coll.Find(nil).Iter()
	var data HealingEvent
	for iter.Next(&data) {
		err = healingEventToEvent(&data)
		if err != nil {
			return err
		}
	}
	return iter.Close()
}
