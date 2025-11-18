import io
import base64
import zipfile

from anyrun import RunTimeException
from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector, AndroidConnector

from anyrun_sandbox.config import Config


class AnyRunSubmitter:
    """
    Implements functionality for sending MISP entities to the ANY.RUN sandbox
    """
    def __init__(self, request: dict) -> None:
        self._request = request
        self._config: dict = request.get("config")

    def submit(self) -> str:
        """
        Configures ANY.RUN Sandbox environment and executes the analysis

        :return: ANY.RUN Sandbox analysis uuid
        """
        self._parse_config()
        self._sanitize_config()

        if self._os_type == "windows":
            with SandboxConnector.windows(self._token, Config.INTEGRATION) as connector:
                analysis_uuid = self._process_analysis(connector)
        elif self._os_type in ("ubuntu", "debian"):
            with SandboxConnector.linux(self._token, Config.INTEGRATION) as connector:
                analysis_uuid = self._process_analysis(connector)
        elif self._os_type == "android":
            with SandboxConnector.android(self._token, Config.INTEGRATION) as connector:
                analysis_uuid = self._process_analysis(connector)
        else:
            raise RunTimeException(
                f"Received invalid OS type: {self._os_type}. Supports: windows, ubuntu, debian, android"
            )

        return analysis_uuid

    def _parse_config(self) -> None:
        """
        Configures analysis options according to the chosen environment

        """
        self._token = self._config.pop("api_key", "")
        self._os_type = self._config.pop("os_type", "")

        if not any((self._token, self._os_type)):
            raise RunTimeException(f"ANYRUN Sandbox API-KEY and OS type must be specified.")

        if "url" in self._request:
            self._prepare_url_params()
            self._config["obj_url"] = self._request.get("url")
        elif "malware-sample" in self._request:
            self._prepare_file_params()
            self._prepare_file_content("malware-sample")
        elif "attachment" in self._request:
            self._prepare_file_params()
            self._prepare_file_content("attachment")
        else:
            raise RunTimeException("Received invalid Object. Supports: url, attachment, malware-sample.")

    def _process_analysis(self, connector: WindowsConnector | LinuxConnector | AndroidConnector) -> str:
        """
        Executes analysis

        :param connector: Instance of the ANY.RUN connector
        :return: ANY.RUN Sandbox analysis uuid
        """
        connector.check_authorization()

        if "obj_url" in self._config:
            analysis_uuid = connector.run_url_analysis(**self._config)
        else:
            analysis_uuid = connector.run_file_analysis(**self._config)
        return analysis_uuid

    def _prepare_url_params(self) -> None:
        """
        Prepares analysis configuration for the url submission
        """
        if self._os_type != "windows":
            self._config.pop("env_version", "")
            self._config.pop("env_bitness", "")
            self._config.pop("env_type", "")

        self._config.pop("obj_ext_extension", "")
        self._config.pop("obj_ext_startfolder", "")
        self._config.pop("obj_ext_cmd", "")
        self._config.pop("obj_force_elevation", "")
        self._config.pop("run_as_root", "")


    def _prepare_file_params(self) -> None:
        """
        Prepares analysis configuration for the file submission
        """
        self._config.pop("obj_ext_browser", "")

        if self._os_type == "windows":
            self._config.pop("run_as_root", "")
        elif self._os_type in ("ubuntu", "debian"):
            self._config.pop("env_version", "")
            self._config.pop("env_bitness", "")
            self._config.pop("env_type", "")
            self._config.pop("obj_force_elevation", "")
            self._config["env_os"] = self._os_type
        elif self._os_type == "android":
            self._config.pop("env_version", "")
            self._config.pop("env_bitness", "")
            self._config.pop("env_type", "")
            self._config.pop("obj_force_elevation", "")
            self._config.pop("obj_ext_startfolder", "")
            self._config.pop("run_as_root", "")

    def _prepare_file_content(self, sample_type: str) -> None:
        """
        Prepares file content to the analysis

        :param sample_type: Attachment or malware-sample MISP entity
        """
        if sample_type == "attachment":
            filename = self._request.get("attachment")
            file_content = self._extract_file_content(self._request.get("data"))
        else:
            filename = self._request.get("malware-sample").split("|", 1)[0]
            file_content = self._extract_file_content(self._request.get("data"), is_encoded=True)

        self._config["filename"] = filename
        self._config["file_content"] = file_content

    def _sanitize_config(self) -> None:
        """
        Removes empty parameters from the analysis configuration
        """
        temp_config = dict()

        for key, value in self._config.items():
            if value is not None:
                temp_config[key] = value

        self._config = temp_config

    @staticmethod
    def _extract_file_content(file_content: str, is_encoded: bool = False) -> bytes:
        """
        Extracts file content from the **malware-sample** MISP entity

        :param file_content: Base64 file content
        :param is_encoded: Marks if **malware-sample** or **attachment** entity received
        :return: File bytes payload
        """
        data = base64.b64decode(file_content)

        if is_encoded:
            with zipfile.ZipFile(io.BytesIO(data)) as file:
                data = file.read(file.namelist()[0], pwd=b"infected")

        return data
