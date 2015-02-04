// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	gerrors "errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sajari/fuzzy"
	"github.com/tsuru/tsuru/errors"
	"github.com/tsuru/tsuru/fs"
	"launchpad.net/gnuflag"
)

var ErrAbortCommand = gerrors.New("")

type exiter interface {
	Exit(int)
}

type osExiter struct{}

func (e osExiter) Exit(code int) {
	os.Exit(code)
}

type Lookup func(context *Context) error

type Manager struct {
	Commands      map[string]Command
	topics        map[string]string
	name          string
	stdout        io.Writer
	stderr        io.Writer
	stdin         io.Reader
	version       string
	versionHeader string
	e             exiter
	original      string
	wrong         bool
	lookup        Lookup
}

func NewManager(name, ver, verHeader string, stdout, stderr io.Writer, stdin io.Reader, lookup Lookup) *Manager {
	manager := &Manager{name: name, version: ver, versionHeader: verHeader, stdout: stdout, stderr: stderr, stdin: stdin, lookup: lookup}
	manager.Register(&help{manager})
	manager.Register(&version{manager})
	return manager
}

func BuildBaseManager(name, version, versionHeader string, lookup Lookup) *Manager {
	m := NewManager(name, version, versionHeader, os.Stdout, os.Stderr, os.Stdin, lookup)
	m.Register(&login{})
	m.Register(&logout{})
	m.Register(&targetList{})
	m.Register(&targetAdd{})
	m.Register(&targetRemove{})
	m.Register(&targetSet{})
	m.RegisterTopic("target", targetTopic)
	return m
}

func (m *Manager) Register(command Command) {
	if m.Commands == nil {
		m.Commands = make(map[string]Command)
	}
	var name string
	if named, ok := command.(NamedCommand); ok {
		name = named.Name()
	} else {
		name = command.Info().Name
	}
	_, found := m.Commands[name]
	if found {
		panic(fmt.Sprintf("command already registered: %s", name))
	}
	m.Commands[name] = command
}

func (m *Manager) RegisterDeprecated(command Command, oldName string) {
	if m.Commands == nil {
		m.Commands = make(map[string]Command)
	}
	var name string
	if named, ok := command.(NamedCommand); ok {
		name = named.Name()
	} else {
		name = command.Info().Name
	}
	_, found := m.Commands[name]
	if found {
		panic(fmt.Sprintf("command already registered: %s", name))
	}
	m.Commands[name] = command
	m.Commands[oldName] = &DeprecatedCommand{Command: command, oldName: oldName}
}

func (m *Manager) RegisterTopic(name, content string) {
	if m.topics == nil {
		m.topics = make(map[string]string)
	}
	_, found := m.topics[name]
	if found {
		panic(fmt.Sprintf("topic already registered: %s", name))
	}
	m.topics[name] = content
}

func (m *Manager) Run(args []string) {
	var status int
	if len(args) == 0 {
		args = append(args, "help")
	}
	for i, j := range args {
		if j == "--help" {
			args = append(args[0:i], args[i+1:]...)
			args = append([]string{"help"}, args...)
		}
	}
	if args[0] == "--version" {
		args[0] = "version"
	}
	flagset := gnuflag.NewFlagSet("tsuru flags", gnuflag.ExitOnError)
	verbosity := flagset.Int("verbosity", 0, "Verbosity: 1 => print HTTP requests; 2 => print HTTP requests/responses")
	flagset.IntVar(verbosity, "v", 0, "Verbosity: 1 => print HTTP requests; 2 => print HTTP requests/responses")
	parseErr := flagset.Parse(false, args)
	args = flagset.Args()
	if parseErr != nil {
		fmt.Fprint(m.stderr, parseErr)
		m.finisher().Exit(1)
		return
	}
	args = m.normalizeCommandArgs(args)
	name := args[0]
	command, ok := m.Commands[name]
	if !ok {
		if msg, isTopic := m.tryImplicitTopic(name); isTopic {
			fmt.Fprint(m.stdout, msg)
			return
		}
		if m.lookup != nil {
			context := Context{args, m.stdout, m.stderr, m.stdin}
			err := m.lookup(&context)
			if err != nil {
				msg := ""
				if os.IsNotExist(err) {
					msg = fmt.Sprintf("%s: %q is not a tsuru command. See %q.\n", os.Args[0], args[0], "tsuru help")
					msg += fmt.Sprintf("\nDid you mean?\n")
					var keys []string
					for key := range m.Commands {
						keys = append(keys, key)
					}
					sort.Strings(keys)
					for _, key := range keys {
						levenshtein := fuzzy.Levenshtein(&key, &args[0])
						if levenshtein < 3 || strings.HasPrefix(key, args[0]) {
							msg += fmt.Sprintf("\t%s\n", key)
						}
					}
				} else {
					msg = err.Error()
				}
				fmt.Fprint(m.stderr, msg)
				m.finisher().Exit(1)
			}
			return
		}
		fmt.Fprintf(m.stderr, "Error: command %q does not exist\n", args[0])
		m.finisher().Exit(1)
		return
	}
	args = args[1:]
	info := command.Info()
	if flagged, ok := command.(FlaggedCommand); ok {
		flagset := flagged.Flags()
		err := flagset.Parse(true, args)
		if err != nil {
			fmt.Fprint(m.stderr, err)
			m.finisher().Exit(1)
			return
		}
		args = flagset.Args()
	}
	if length := len(args); (length < info.MinArgs || (info.MaxArgs > 0 && length > info.MaxArgs)) &&
		name != "help" {
		m.wrong = true
		m.original = info.Name
		command = m.Commands["help"]
		args = []string{name}
		status = 1
	}
	context := Context{args, m.stdout, m.stderr, m.stdin}
	client := NewClient(&http.Client{}, &context, m)
	client.Verbosity = *verbosity
	err := command.Run(&context, client)
	if err != nil {
		errorMsg := err.Error()
		httpErr, ok := err.(*errors.HTTP)
		if ok && httpErr.Code == http.StatusUnauthorized && name != "login" {
			errorMsg = `You're not authenticated or your session has expired. Please use "login" command for authentication.`
		}
		if !strings.HasSuffix(errorMsg, "\n") {
			errorMsg += "\n"
		}
		if err != ErrAbortCommand {
			io.WriteString(m.stderr, "Error: "+errorMsg)
		}
		status = 1
	}
	m.finisher().Exit(status)
}

func (m *Manager) finisher() exiter {
	if m.e == nil {
		m.e = osExiter{}
	}
	return m.e
}

func (m *Manager) tryImplicitTopic(name string) (string, bool) {
	var group []string
	for k := range m.Commands {
		if strings.HasPrefix(k, name+"-") {
			group = append(group, k)
		}
	}
	topic, isExplicit := m.topics[name]
	if len(group) > 0 {
		topic += fmt.Sprintf("\nThe following commands are available in the %q topic:\n\n", name)
		topic += m.dumpCommands(group)
	} else if !isExplicit {
		return "", false
	}
	return topic, true
}

func (m *Manager) dumpCommands(commands []string) string {
	sort.Strings(commands)
	var output string
	for _, command := range commands {
		description := m.Commands[command].Info().Desc
		description = strings.Split(description, "\n")[0]
		description = strings.Split(description, ".")[0]
		if len(description) > 2 {
			description = strings.ToUpper(description[0:1]) + description[1:]
		}
		output += fmt.Sprintf("  %-20s %s\n", command, description)
	}
	output += fmt.Sprintf("\nUse %s help <commandname> to get more information about a command.\n", m.name)
	return output
}

func (m *Manager) normalizeCommandArgs(args []string) []string {
	name := args[0]
	if _, ok := m.Commands[name]; ok {
		return args
	}
	replaced := strings.Replace(name, ":", "-", -1)
	if _, ok := m.Commands[replaced]; ok {
		args[0] = replaced
		return args
	}
	newArgs := []string{replaced}
	var i int
	for i = 1; i < len(args); i++ {
		part := args[i]
		newArgs[0] += "-" + part
		if _, ok := m.Commands[newArgs[0]]; ok {
			break
		}
	}
	if i < len(args) {
		newArgs = append(newArgs, args[i+1:]...)
		return newArgs
	}
	return args
}

func (m *Manager) discoverTopics() []string {
	freq := map[string]int{}
	for cmdName, cmd := range m.Commands {
		if _, isDeprecated := cmd.(*DeprecatedCommand); isDeprecated {
			continue
		}
		idx := strings.Index(cmdName, "-")
		if idx != -1 {
			freq[cmdName[:idx]] += 1
		}
	}
	for topic := range m.topics {
		freq[topic] = 999
	}
	var result []string
	for topic, count := range freq {
		if count > 1 {
			result = append(result, topic)
		}
	}
	sort.Strings(result)
	return result
}

type Command interface {
	Info() *Info
	Run(context *Context, client *Client) error
}

type NamedCommand interface {
	Command
	Name() string
}

type FlaggedCommand interface {
	Command
	Flags() *gnuflag.FlagSet
}

type DeprecatedCommand struct {
	Command
	oldName string
}

func (c *DeprecatedCommand) Run(context *Context, client *Client) error {
	fmt.Fprintf(context.Stderr, "WARNING: %q has been deprecated, please use %q instead.\n\n", c.oldName, c.Command.Info().Name)
	return c.Command.Run(context, client)
}

func (c *DeprecatedCommand) Flags() *gnuflag.FlagSet {
	if cmd, ok := c.Command.(FlaggedCommand); ok {
		return cmd.Flags()
	}
	return gnuflag.NewFlagSet("", gnuflag.ContinueOnError)
}

type Context struct {
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

type Info struct {
	Name    string
	MinArgs int
	MaxArgs int
	Usage   string
	Desc    string
}

// Implementing the Commandable interface allows extending
// the tsr command line interface
type Commandable interface {
	Commands() []Command
}

// Implementing the AdminCommandable interface allows extending
// the tsuru-admin command line interface
type AdminCommandable interface {
	AdminCommands() []Command
}

type help struct {
	manager *Manager
}

func (c *help) Info() *Info {
	return &Info{
		Name:  "help",
		Usage: "command [args]",
	}
}

func (c *help) Run(context *Context, client *Client) error {
	const deprecatedMsg = "WARNING: %q is deprecated. Showing help for %q instead.\n\n"
	output := fmt.Sprintf("%s version %s.\n\n", c.manager.name, c.manager.version)
	if c.manager.wrong {
		output += fmt.Sprint("ERROR: wrong number of arguments.\n\n")
	}
	if len(context.Args) > 0 {
		if cmd, ok := c.manager.Commands[context.Args[0]]; ok {
			if deprecated, ok := cmd.(*DeprecatedCommand); ok {
				fmt.Fprintf(context.Stderr, deprecatedMsg, deprecated.oldName, cmd.Info().Name)
			}
			info := cmd.Info()
			output += fmt.Sprintf("Usage: %s %s\n", c.manager.name, info.Usage)
			output += fmt.Sprintf("\n%s\n", info.Desc)
			if info.MinArgs > 0 {
				output += fmt.Sprintf("\nMinimum # of arguments: %d", info.MinArgs)
			}
			if info.MaxArgs > 0 {
				output += fmt.Sprintf("\nMaximum # of arguments: %d", info.MaxArgs)
			}
			output += fmt.Sprint("\n")
		} else if msg, ok := c.manager.tryImplicitTopic(context.Args[0]); ok {
			output += msg
		} else {
			return fmt.Errorf("command %q does not exist.", context.Args[0])
		}
	} else {
		output += fmt.Sprintf("Usage: %s %s\n\nAvailable commands:\n", c.manager.name, c.Info().Usage)
		var commands []string
		for name, cmd := range c.manager.Commands {
			if _, ok := cmd.(*DeprecatedCommand); !ok {
				commands = append(commands, name)
			}
		}
		output += c.manager.dumpCommands(commands)
		if len(c.manager.topics) > 0 {
			output += fmt.Sprintln("\nAvailable topics:")
			for _, topic := range c.manager.discoverTopics() {
				description := c.manager.topics[topic]
				lineBreak := strings.Index(description, "\n")
				if lineBreak != -1 {
					description = description[:lineBreak]
				}
				output += fmt.Sprintf("  %-20s %s\n", topic, description)
			}
			output += fmt.Sprintf("\nUse %s help <topicname> to get more information about a topic.\n", c.manager.name)
		}
	}
	io.WriteString(context.Stdout, output)
	return nil
}

type version struct {
	manager *Manager
}

func (c *version) Info() *Info {
	return &Info{
		Name:    "version",
		MinArgs: 0,
		Usage:   "version",
		Desc:    "display the current version",
	}
}

func (c *version) Run(context *Context, client *Client) error {
	fmt.Fprintf(context.Stdout, "%s version %s.\n", c.manager.name, c.manager.version)
	return nil
}

func ExtractProgramName(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

var fsystem fs.Fs

func filesystem() fs.Fs {
	if fsystem == nil {
		fsystem = fs.OsFs{}
	}
	return fsystem
}

// validateVersion checks whether current version is greater or equal to
// supported version.
func validateVersion(supported, current string) bool {
	var (
		bigger bool
		limit  int
	)
	if supported == "" || supported == current {
		return true
	}
	partsSupported := strings.Split(supported, ".")
	partsCurrent := strings.Split(current, ".")
	if len(partsSupported) > len(partsCurrent) {
		limit = len(partsCurrent)
		bigger = true
	} else {
		limit = len(partsSupported)
	}
	for i := 0; i < limit; i++ {
		current, err := strconv.Atoi(partsCurrent[i])
		if err != nil {
			return false
		}
		supported, err := strconv.Atoi(partsSupported[i])
		if err != nil {
			return false
		}
		if current < supported {
			return false
		}
		if current > supported {
			return true
		}
	}
	if bigger {
		return false
	}
	return true
}
