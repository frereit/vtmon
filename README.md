# VTMon

VTMon (VirusTotal Monitor) is a simple tool to send a notification when a hash publicly appears on [VirusTotal](https://www.virustotal.com).

VTMon requires a free VirusTotal API key to function. By default, it fully utilizes the available API quota, but the quota can be manually overriden to make room for other applications too.

## Usage

Notifications are handled with [apprise](https://github.com/caronc/apprise), a universal notification library. It supports [a lot of providers](https://github.com/caronc/apprise), refer to their documentation to create the notification URLs.

The CLI usage is quite straightforward, you supply a list of hashes, files with hashes, and notification endpoints, and VTMon checks all the hashes as frequently as allowed by VirusTotal API limits, and sends out a notification if new hashes appear on VirusTotal:

```bash
vtmon \
    --api-key xxxx \
    --notify 'slack://deadbeef/cafeaffe/xxyyzz/#vtmon' \
    --notify 'mqtt://127.0.0.1/vtmon' \
    --hash 'cb7751a80fa338d35362e861ee18fe2a' \
    --hash 'b1ebd9ce877bc7c0bed2e0079596ae63d1a4b2e8 comments are supported' \
    --hash @newline_seperated_file.txt
```

Any characters after the end of the hash are treated as a comment. This makes the input format compatible with the output of `sha256sum` and similar utilities. For example, you can use `sha256sum * > hashes.txt` to create a file with the hashes of all files in the current folder, and the notifications will automatically include the names of the files that matched.

## Installation

```bash
pipx install git+https://github.com/frereit/vtmon
```

## CLI Help

```bash
$ vtmon --help
usage: vtmon [-?] [--api-key API_KEY] [--daily-quota DAILY_QUOTA] [--hourly-quota HOURLY_QUOTA] [-h HASH] [-n NOTIFY]

VTMon queries Virustotal for a list of file hashes and sends a notification if any file is found.

options:
  -?, --help
  --api-key API_KEY     A VirusTotal API key. If omitted, the VIRUSTOTAL_API_KEY environment variable will be used.
  --daily-quota DAILY_QUOTA
                        Specifies an explicit daily quota for the API key, which will be used for the query interval. If omitted, the daily quota will be retrieved from the
                        VirusTotal API.
  --hourly-quota HOURLY_QUOTA
                        Specifies an explicit hourly quota for the API key, which will be used when querying multiple hashes. If omitted, the hourly quota will be retrieved
                        from the VirusTotal API.
  -h HASH, --hash HASH  A hash to query. May be specified multiple times to query multiple hashes. If the specified value starts with "@", the argument will be treated as a
                        newline-delimeted list of hashes. This file will be re-read on every check, so new hashes will be loaded without requiring a restart. Each hash may
                        either MD5/SHA1/SHA256. Any content after the hash will be treated as a comment and included in the notification.
  -n NOTIFY, --notify NOTIFY
                        An apprise URL to send a notification to when one or more hashes are found. May be specified multiple times to send notifications to multiple
                        providers.
```
