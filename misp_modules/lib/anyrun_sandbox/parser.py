import json
from http import HTTPStatus
from pymisp import MISPEvent, MISPObject

from anyrun import RunTimeException
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector, AndroidConnector


class AnyRunParser:
    """
    Implements functionality for parsing ANY.RUN Sandbox reports into MISP objects and attributes
    """
    def __init__(
        self,
        config: dict[str, str],
        analysis_uuid: str,
        connector: WindowsConnector | LinuxConnector | AndroidConnector
    ) -> None:
        self._event = MISPEvent()
        self._connector = connector
        self._analysis_uuid = analysis_uuid
        self._config = config

    def generate_results(self) -> dict[str, dict]:
        """
        Enriches the results dictionary with ANY.RUN report objects

        :return: MISP results dictionary
        """
        self._check_analysis_completion()

        summary = self._connector.get_analysis_report(self._analysis_uuid)

        self._add_report()

        if self._check_option("IOCs"):
            self._add_indicators()

        if self._check_option("Tags"):
            self._add_tags(summary)

        if self._check_option("MITRE"):
            self._add_mitre_galaxies(summary)

        results = json.loads(self._event.to_json())

        return {
            "results": {
                key: results[key]
                for key in ("Attribute", "Object", "Tag")
                if (key in results and results[key])
            }
        }

    def _check_analysis_completion(self) -> None:
        """
        Checks if ANY.RUN Sandbox analysis is completed

        :raises RunTimeException: If analysis is not completed
        """
        status = self._connector.get_analysis_report(self._analysis_uuid).get("data").get("status")

        if status != "done":
            raise RunTimeException(
                f"Analysis is running. Please, wait a few minutes to request a report",
                HTTPStatus.BAD_REQUEST
            )

    def _add_indicators(self) -> None:
        """
        Converts ANY.RUN indicators to the MISP attributes
        """
        if iocs := self._connector.get_analysis_report(self._analysis_uuid, report_format="ioc"):
            for ioc in iocs:
                if ioc.get("type") in ("domain", "ip", "sha256") and ioc.get("reputation") in (1, 2):
                    ioc_type = ioc.get("type")
                    ioc_reputation = {1: "Suspicious", 2: "Malicious"}.get(ioc.get("reputation"))
                    attribute = self._event.add_attribute(
                        type=ioc_type if ioc_type in ("domain", "sha256") else "ip-dst",
                        value=ioc.get("ioc"),
                        categories="Network activity" if ioc_type in ("ip", "domain") else "Payload delivery",
                        comment=f"{ioc_reputation} IoC from https://app.any.run/tasks/{self._analysis_uuid}."
                    )

                    attribute.add_tag("ANY.RUN Sandbox")

    def _add_tags(self, summary: dict) -> None:
        """
        Converts ANY.RUN analysis tags to the MISP tags

        :param summary: ANY.RUN Sandbox report
        """
        self._event.add_tag("ANY.RUN Sandbox")
        if tags := summary.get("data").get("analysis").get("tags"):
            for tag in tags:
                self._event.add_tag(tag.get("tag"))

    def _add_mitre_galaxies(self, summary: dict) -> None:
        """
        Converts ANY.RUN analysis mitre techniques to the MISP Galaxies

        :param summary: ANY.RUN Sandbox report
        """
        if mitre_techniques := summary.get("data").get("mitre"):
            for entry in mitre_techniques:
                if entry:
                    mitre_name = entry.get("name")
                    mitre_id = entry.get("id")
                    self._event.add_tag(f'misp-galaxy:mitre-attack-pattern="{mitre_name} - {mitre_id}"')

    def _add_report(self) -> None:
        """
        Converts ANY.RUN analysis HTML report and external references to the MISP attributes

        :return:
        """
        report = self._connector.get_analysis_report(self._analysis_uuid, report_format="html")

        self._event.add_attribute(
            type="text",
            value=f"ANY.RUN Sandbox verdict: {self._connector.get_analysis_verdict(self._analysis_uuid)}",
            categories="Other",
            comment="ANYRUN Sandbox Analysis verdict."
        )

        self._event.add_attribute(
            type="link",
            value=f"https://app.any.run/tasks/{self._analysis_uuid}",
            categories="External analysis",
            comment="ANYRUN Sandbox Analysis report."
        )

        self._event.add_attribute(
            type="attachment",
            value="report.html",
            data=report.encode(),
            comment="ANYRUN Sandbox Analysis report."
        )

    def _check_option(self, option_name: str) -> bool:
        """
        Checks if option is active

        :param option_name: Option name to check
        :return: True if option is enabled else False
        """
        return bool(int(self._config.get(option_name)))
