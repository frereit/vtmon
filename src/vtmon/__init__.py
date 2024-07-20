from dataclasses import dataclass
import datetime
import time
from typing import Generator, Iterable, Optional
import re
import logging

import vt
import apprise

__version__ = "1.0.0"


@dataclass
class HashInfo:
    value: str
    comment: Optional[str]

    @staticmethod
    def from_str(hash_info: str) -> "HashInfo":
        matched = re.match(
            r"([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(.*)", hash_info
        )
        if not matched:
            raise ValueError(f"Invalid hash info string: {hash_info}")
        return HashInfo(matched.group(1), matched.group(2))

    @staticmethod
    def from_args(args: list[str]) -> list["HashInfo"]:
        infos = []
        for arg in args:
            if arg.startswith("@"):
                with open(arg[1:]) as f:
                    for line in f:
                        if line == "":
                            continue
                        infos.append(HashInfo.from_str(line))
            else:
                infos.append(HashInfo.from_str(arg))
        return infos


class VTMon:
    def __init__(
        self,
        api_key: str,
        notifiers: list[str],
        daily_quota: Optional[int] = None,
        hourly_quota: Optional[int] = None,
    ):
        """Initialize a new VTMon instance

        Args:
            api_key (str): The VirusTotal API key to use
            notifiers (list[str]): A list of apprise URLs to notify when new hashes are found.
            daily_quota (int, optional): Specifies an explicit daily quota for the API key, which will be used for the query interval.
            If omitted, the daily quota will be retrieved from the VirusTotal API.
            hourly_quota (int, optional): Specifies an explicit hourly quota for the API key, which will be used when querying multiple hashes.
            If omitted, the hourly quota will be retrieved from the VirusTotal API.
        """

        self._client = vt.Client(api_key, "vtmon")
        """The VirusTotal Client interfaces with the VirusTotal API"""

        self._apprise = apprise.Apprise()
        self._apprise.add(notifiers)

        self._daily_quota = daily_quota
        """Maximum amount of VirusTotal API requests per day."""

        self._hourly_quota = hourly_quota
        """Maximum amount of VirusTotal API requests per hour."""

        self._founds = dict()

        if daily_quota is None or hourly_quota is None:
            logging.debug("Getting API limits from VirusTotal API")
            quota = self._client.get_data(f"/users/{api_key}/overall_quotas")
            self._daily_quota = (
                self._daily_quota or quota["api_requests_daily"]["user"]["allowed"]
            )
            self._hourly_quota = (
                self._hourly_quota or quota["api_requests_hourly"]["user"]["allowed"]
            )
            logging.debug(f"{self._daily_quota = } {self._hourly_quota = }")

    def query(self, hash: str) -> Optional[vt.Object]:
        try:
            return self._client.get_object(f"/files/{hash}")
        except vt.APIError:
            # vt throws an APIError if the file is not found.
            return None

    def query_new(self, hashes: list[str]) -> tuple[dict[str, vt.Object], int]:
        """Query the VirusTotal API for any of a list of hashes, waiting according to the quota limits between requests. Hashes already seen by this VTMon instance will not be looked up again.

        Args:
            hashes (list[str]): Hashes to query.

        Returns:
            dict[str, vt.Object]: The found hashes and their corresponding files.
            int: The number of requests made to VirusTotal.
        """
        request_delay_s = 3600 / self._hourly_quota  # 3600 seconds in an hour
        founds = {}
        reqs = 0
        logging.info(
            f"Looking up {len(hashes)} hashes with a delay of {request_delay_s}"
        )
        for hash in hashes:
            # Has this hash already been found on VirusTotal?
            if hash in self._founds.keys():
                founds[hash] = self._founds[hash]
                continue

            reqs += 1
            if file := self.query(hash):
                founds[hash] = file
                self._founds[hash] = file
            # Note: This intentionally overestimates the sleep time, because it ignores the time taken for the request itself.
            # I'd rather wait slightly longer than not long enough and run into API limits.
            time.sleep(request_delay_s)
        return founds, reqs

    def query_forever(self) -> Generator[dict[str, vt.Object], list[str], None]:
        """Query the VirusTotal API forever, waiting appropriately between requests.

        The hashes to lookup are taken from the return value of `yield`, so they must be passed
        to the generator using `send`.

        Yields:
            dict[str, vt.Object]: A new set of found hashes.
        """

        hashes = yield {}
        while True:
            founds, reqs = self.query_new(hashes)
            # Assume reqs is a good estimate for how many requests we make to VirusTotal "per round".
            # 86400 seconds in an hour.
            query_delay_s = 86400 / self._hourly_quota * reqs
            hashes = yield founds
            time.sleep(max(query_delay_s, 5))  # Wait at least 5 seconds

    def notify(self, hash_infos: list[HashInfo], founds: dict[str, vt.Object]):
        """Send out notifications for all hashes in `founds` to all notifiers in `notifiers`.

        Args:
            hash_infos (list[HashInfo]): A list of hashes which may include comments to be included in the notifications.
            founds (dict[str, vt.Object]): The found hashes and their files.
        """

        title = f"{len(founds)} new hash{'es were' if len(founds) > 1 else ' was'} found on VirusTotal"
        logging.info(f"{title}, sending out notifications")

        body = ""
        for found_hash, found_file in founds.items():
            infos = list(filter(lambda i: i.value == found_file.md5, hash_infos))
            infos += list(filter(lambda i: i.value == found_file.sha1, hash_infos))
            infos += list(filter(lambda i: i.value == found_file.sha256, hash_infos))
            formatted = f"* {found_hash}"
            if infos:
                formatted += f" ({', '.join(i.comment.strip() for i in infos)})"
            # The .replace is needed because vt-py uses the deprecated .utcfromtimestamp API.
            # https://github.com/VirusTotal/vt-py/pull/194
            formatted += f"""
First seen by VirusTotal: {found_file.first_submission_date.replace(tzinfo=datetime.UTC).astimezone().isoformat()}
Last seen by VirusTotal: {found_file.last_submission_date.replace(tzinfo=datetime.UTC).astimezone().isoformat()}
URL: https://www.virustotal.com/gui/file/{found_hash}/details

"""
            body += formatted
        self._apprise.notify(body=body, title=title)
