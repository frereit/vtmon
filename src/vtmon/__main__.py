import argparse
import os

from vtmon import VTMon, HashInfo


def main():
    parser = argparse.ArgumentParser(
        "vtmon",
        description="VTMon queries Virustotal for a list of file hashes and sends a notification if any file is found.",
        add_help=False,
    )
    parser.add_argument("-?", "--help", action="help")

    parser.add_argument(
        "--api-key",
        default=os.environ.get("VIRUSTOTAL_API_KEY"),
        help="""A VirusTotal API key. If omitted, the VIRUSTOTAL_API_KEY environment variable will be used.""",
    )

    parser.add_argument(
        "--daily-quota",
        default=None,
        help="""Specifies an explicit daily quota for the API key, which will be used for the query interval.
                If omitted, the daily quota will be retrieved from the VirusTotal API.""",
    )
    parser.add_argument(
        "--hourly-quota",
        default=None,
        help="""Specifies an explicit hourly quota for the API key, which will be used when querying multiple hashes.
                If omitted, the hourly quota will be retrieved from the VirusTotal API.""",
    )

    parser.add_argument(
        "-h",
        "--hash",
        default=[],
        action="append",
        help="""A hash to query. May be specified multiple times to query multiple hashes.
                If the specified value starts with "@", the argument will be treated as a newline-delimeted list of hashes.
                This file will be re-read on every check, so new hashes will be loaded without requiring a restart.
                Each hash may either MD5/SHA1/SHA256. Any content after the hash will be treated as a
                comment and included in the notification.""",
    )
    parser.add_argument(
        "-n",
        "--notify",
        default=[],
        action="append",
        help="""An apprise URL to send a notification to when one or more hashes are found.
                May be specified multiple times to send notifications to multiple providers.""",
    )
    args = parser.parse_args()

    if not args.api_key:
        raise ValueError(
            "No API key specified! Either set the VIRUSTOTAL_API_KEY environment variable or use --api-key"
        )

    vt = VTMon(args.api_key, args.notify, args.daily_quota, args.hourly_quota)

    querier = vt.query_forever()
    next(querier)  # We need to send in hashes before we can get any founds
    while True:
        infos = HashInfo.from_args(args.hash)
        hashes = (i.value for i in infos)
        founds = querier.send(hashes)
        if founds:
            vt.notify(infos, founds)


if __name__ == "__main__":
    main()
