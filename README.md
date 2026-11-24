# Description

This project is a parsing library for Windows EVTX log files. Our goal was to
make a resilient parser which provides a nice interface to interact with the
events programmatically. We opted for an event representation as a `map` which
is perfect to represent BinXML tree like structure. As a consequence, it is very
easy to (de)serialize events with the standard Go API. We also provide the
necessary APIs to query specific values of the event.

An example is better than a long talk:
 ```json
 {
  "Event": {
    "EventData": {
      "Hashes": "SHA1=F04EE61F0C6766590492CD3D9E26ECB0D4F501D8,MD5=68D9577E9E9E3A3DF0348AB3B86242B1,SHA256=7AE581DB760BCEEE4D18D6DE7BB98F46584656A65D9435B4E0C4223798F416D2,IMPHASH=ADB9F71ACD4F7D3CF761AB6C59A7F1E5",
      "Image": "C:\\Windows\\splwow64.exe",
      "ImageLoaded": "C:\\Windows\\System32\\dwmapi.dll",
      "ProcessGuid": "B2796A13-E44F-5880-0000-001006E40F00",
      "ProcessId": "4952",
      "Signature": "Microsoft Windows",
      "Signed": "true",
      "UtcTime": "2017-01-19 16:07:45.279"
    },
    "System": {
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "DESKTOP-5SUA567",
      "Correlation": {},
      "EventID": "7",
      "EventRecordID": "116913",
      "Execution": {
        "ProcessID": "1760",
        "ThreadID": "1952"
      },
      "Keywords": "0x8000000000000000",
      "Level": "4",
      "Opcode": "0",
      "Provider": {
        "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
        "Name": "Microsoft-Windows-Sysmon"
      },
      "Security": {
        "UserID": "S-1-5-18"
      },
      "Task": "7",
      "TimeCreated": {
        "SystemTime": "2017-01-19T16:07:45Z"
      },
      "Version": "3"
    }
  }
}
 ```

# Command Line Tools

Some utilities are packaged with this library and can be used without any
dependencies.

## evtxdump

Evtxdump can be used to print in JSON format the events of several EVTX files.
The events are printed ordered by time and not by their order of appearance in
the file.

Evtxdump can also be used to carve Events from raw data. It can be very convenient
to recover corrupted EVTX or to carve deleted EVTX files from disk images. We advise
you to select the option `-t` made to print the timestamp as integer at the
beginning of each line of the output. This can be used later on to sort the events
for timelining purposes (with `sort` command for instance).

```
Usage of evtxdump: evtxdump [OPTIONS] FILES...
  -V	Show version and exit
  -brURL string
        Kafka Broker URL
  -c	Carve events from file
  -cID string
        Kafka client ID
  -cpuprofile string
    	write cpu profile to this file
  -d	Enable debug mode
  -l int
    	Limit the number of chunks to parse (carving mode only)
  -memprofile string
    	write memory profile to this file
  -o int
    	Offset to start from (carving mode only)
  -start value
    	Print logs starting from start
  -stop value
    	Print logs before stop
  -t	Prints event timestamp (as int) at the beginning of line to make sorting easier
  -tag string
        special tag for matching purpose on remote collector
  -tcp string
        tcp socket address for sending output to remote site over TCP. Only for type tcp
  -topic string
        Kafka topic
  -http string
        url for sending output to remote site over HTTP. Only for type http
  -type string
        Type of remote log collector. "http" - JSON-over-HTTP, "tcp" - JSON-over-TCP, "kafka" -  Kafka
  -u	Does not care about ordering the events before printing (faster for large files)
```

### docker version evtxdump

```
docker build -t MonaxGT/evtxdump .
docker run -it --rm -v /tmp:/app/data evtxdump /app/data/log.evtx

```

## evtxmon

Evtxmon is a small command line tool used to monitor in realtime the logs as they
appear in the evtx files.

```
Usage: evtxmon [OPTIONS] EVTX-FILE
  -V	Show version information
  -d	Enable debug messages
  -f value
    	Event ids to filter out
  -s	Outputs stats about events processed
  -t value
    	Timeout for the test
  -timeline-abort
    	Enable timeline guard in abort mode: stop monitoring as soon as the (EventRecordID, TimeCreated) timeline goes backwards
  -timeline-strict
    	Enable timeline guard in fail-closed mode: drop out-of-order events (e.g. replayed after a file reopen) with an explicit warning
  -timeline-warn
    	Enable timeline guard: log an explicit warning when events go backwards in (EventRecordID, TimeCreated) but keep publishing them
  -w string
    	Write monitored events to output file
```

# Timeline guard

When an EVTX file is reopened (service restart, file rotation, ...) the
consumer may replay already written events in **disk order**. Those events can
carry `TimeCreated` timestamps and `EventRecordID` values that go backwards
compared to the events already published, which silently corrupts the public
timeline of downstream consumers.

The library ships with an optional `TimelineGuard` (`evtx/timeline.go`) which
binds the public timeline to both identities of every event:

- the record identity: `/Event/System/EventRecordID`
- the event timestamp: `/Event/System/TimeCreated/SystemTime`

The guard considers the timeline healthy as long as both attributes are
monotonically non decreasing:

- equal timestamps are always legal (several events can share the same
  filetime tick) and never raise an alert;
- strictly increasing record ids and timestamps always pass through;
- an exact re-read of the same event (same record id, same timestamp) is
  tolerated;
- a simultaneous regression of the record id and the timestamp is reported as
  a timeline rewind (`ErrTimelineRewind`), the unmistakable signature of a
  file reopen replaying events in disk order;
- isolated regressions of the record id, of the timestamp, or a record id
  reused with a different timestamp are reported as distinct anomalies
  (`ErrEventRecordRegression`, `ErrTimeRegression`, `ErrDuplicateRecord`).

Three policies are available through `File.EnableTimelineGuard(mode)`:

- `evtx.ModeWarn`: an explicit warning is logged for every anomaly, the event
  is still published (closest to the historical behavior);
- `evtx.ModeFailClosed`: offending events are dropped after an explicit
  warning so that no out-of-order event ever reaches the consumers, while the
  monitoring stream keeps flowing;
- `evtx.ModeAbort`: monitoring stops on the first anomaly.

When the guard is not explicitly enabled, the library behavior is unchanged.
The same guard can also be used standalone:

```go
guard := evtx.NewTimelineGuard(evtx.ModeFailClosed)
for e := range ef.MonitorEvents(stop) {
    if anomaly, abort := guard.CheckEvent(e); anomaly != nil {
        // anomaly.Kind is one of the evtx.Err* sentinel errors
        if abort {
            close(stop)
        }
        continue // fail closed at the consumer level
    }
    publish(e)
}
```

# Known Issues

Some values are not parsed (because we did not have samples to test), so if you
see "UnknowValue: ..." in your output, it means it is not supported. So please
provide us a sample of file so that we can implement it.
