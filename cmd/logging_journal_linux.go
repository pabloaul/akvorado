// SPDX-FileCopyrightText: 2026 Free Mobile
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
)

const journalSocket = "/run/systemd/journal/socket"

func newJournalWriter() *journalLogWriter {
	stream := os.Getenv("JOURNAL_STREAM")
	if stream == "" || (!isJournalStream(os.Stdout, stream) && !isJournalStream(os.Stderr, stream)) {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: journalSocket, Net: "unixgram"})
	if err != nil {
		return nil
	}
	_ = conn.SetWriteBuffer(8 * 1024 * 1024)
	return &journalLogWriter{conn: conn}
}

func isJournalStream(file *os.File, stream string) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stream == strconv.FormatUint(uint64(stat.Dev), 10)+":"+strconv.FormatUint(stat.Ino, 10)
}

type journalLogWriter struct {
	conn io.Writer
}

func (w *journalLogWriter) Write(p []byte) (int, error) {
	return w.WriteLevel(zerolog.NoLevel, p)
}

func (w *journalLogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	entry, err := journalEntry(level, p)
	if err == nil {
		var n int
		n, err = w.conn.Write(entry)
		if err == nil && n != len(entry) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		return os.Stdout.Write(p)
	}
	return len(p), nil
}

func journalEntry(level zerolog.Level, p []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(p, &fields); err != nil {
		return nil, err
	}
	var entry bytes.Buffer
	message := fieldString(fields["message"])
	if message == "" {
		message = strings.TrimSpace(string(p))
	}
	appendJournalField(&entry, "MESSAGE", message)
	appendJournalField(&entry, "PRIORITY", journalPriority(level))
	appendJournalField(&entry, "SYSLOG_IDENTIFIER", filepath.Base(os.Args[0]))
	for name, value := range fields {
		switch name {
		case "message", "level", "time":
			continue
		case "caller":
			caller := fieldString(value)
			file, line, found := strings.Cut(caller, ":")
			if found {
				appendJournalField(&entry, "CODE_FILE", file)
				appendJournalField(&entry, "CODE_LINE", line)
			} else {
				appendJournalField(&entry, "AKVORADO_CALLER", caller)
			}
		default:
			key := journalFieldName(name)
			if key != "" {
				appendJournalField(&entry, key, fieldString(value))
			}
		}
	}
	return entry.Bytes(), nil
}

func journalPriority(level zerolog.Level) string {
	switch level {
	case zerolog.TraceLevel, zerolog.DebugLevel:
		return "7"
	case zerolog.WarnLevel:
		return "4"
	case zerolog.ErrorLevel:
		return "3"
	case zerolog.FatalLevel:
		return "2"
	case zerolog.PanicLevel:
		return "0"
	default:
		return "6"
	}
}

func fieldString(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return string(raw)
}

func journalFieldName(name string) string {
	var b strings.Builder
	b.WriteString("AKVORADO_")
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteRune(c - 'a' + 'A')
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == '-' || c == '_':
			b.WriteByte('_')
		default:
			return ""
		}
	}
	if b.Len() == len("AKVORADO_") {
		return ""
	}
	return b.String()
}

func appendJournalField(entry *bytes.Buffer, name, value string) {
	if strings.ContainsRune(value, '\n') {
		entry.WriteString(name)
		entry.WriteByte('\n')
		_ = binary.Write(entry, binary.LittleEndian, uint64(len(value)))
		entry.WriteString(value)
		entry.WriteByte('\n')
		return
	}
	entry.WriteString(name)
	entry.WriteByte('=')
	entry.WriteString(value)
	entry.WriteByte('\n')
}
