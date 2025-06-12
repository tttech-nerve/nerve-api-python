# Copyright (c) 2024 TTTech Industrial Automation AG.
#
# ALL RIGHTS RESERVED.
# Usage of this software, including source code, netlists, documentation,
# is subject to restrictions and conditions of the applicable license
# agreement with TTTech Industrial Automation AG or its affiliates.
#
# All trademarks used are the property of their respective owners.
#
# TTTech Industrial Automation AG and its affiliates do not assume any liability
# arising out of the application or use of any product described or shown
# herein. TTTech Industrial Automation AG and its affiliates reserve the right to
# make changes, at any time, in order to improve reliability, function or
# design.
#
# Contact Information:
# support@tttech-industrial.com
# TTTech Industrial Automation AG, Schoenbrunnerstrasse 7, 1040 Vienna, Austria

"""Manage OpenSearch releated function on MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSOpenSearch
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     opensearch = MSOpenSearch(ms_handle)
    >>>     opensearch.get_audit()
    <dict of audit request>
"""

import json
import logging
from copy import deepcopy
from datetime import datetime
from datetime import timedelta

import requests


class MSOpenSearch:
    """Create opensearch requets.

    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle):
        self.ms = ms_handle
        self._log = logging.getLogger("User")

        self.query_filter = [{"match_all": {}}]
        self.query_must = []
        self.query_must_not = []
        self.query_should = []

    def __post_payload(self, url, payload):
        """Send post command to opensearch.

        If the request is redirected (code-302 found), a login on ms will be performed.
        """
        response = self.ms.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json", "osd-xsrf": "true"},
            allow_redirects=False,
            accepted_status=[requests.codes.ok, requests.codes.found],
        )
        if response.status_code == requests.codes.found:
            self.ms.login()
            response = self.ms.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json", "osd-xsrf": "true"},
                allow_redirects=False,
                accepted_status=[requests.codes.ok],
            )
        return response.json()

    @staticmethod
    def create_search_bestfield(keyword):
        """Search for simple keyword.

        If keyword contains multiple works, each word will create a match.
        """
        return {"multi_match": {"type": "best_fields", "query": keyword, "lenient": True}}

    @staticmethod
    def create_search_multimatch_phrase(phrase):
        """Search for keyword(s) phrase.

        Phrase can have multiple works, result will contain matches of the complete phrase.
        """
        return {"multi_match": {"type": "phrase", "query": phrase, "lenient": True}}

    @staticmethod
    def create_filter_matchphrase(field, phrase):
        """Define which field should be filtered by a phrase."""
        return {"match_phrase": {field: phrase}}

    def _get_index(self, index: str, past_hours: int, search_filters: list = []):
        """Read specific index from open-search."""
        # Get the current time in UTC
        current_time = datetime.utcnow()
        past_time = current_time - timedelta(hours=past_hours)

        # Format the time as a string
        past_time = past_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        current_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        filter_list = deepcopy(self.query_filter)
        for filter_item in search_filters:
            filter_list.append(filter_item)

        filter_list.append({
            "range": {
                "@timestamp": {
                    "gte": past_time,
                    "lte": current_time,
                    "format": "strict_date_optional_time",
                },
            },
        })

        payload = {
            "params": {
                "index": index,
                "body": {
                    "size": 10000,
                    "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
                    "query": {
                        "bool": {
                            "filter": filter_list,
                            "must": self.query_must,
                            "must_not": self.query_must_not,
                            "should": self.query_should,
                        },
                    },
                    "highlight": {
                        "pre_tags": ["@opensearch-dashboards-highlighted-field@"],
                        "post_tags": ["@/opensearch-dashboards-highlighted-field@"],
                        "fields": {"*": {}},
                    },
                },
            },
        }
        return self.__post_payload("/opensearch/internal/search/opensearch", payload)

    def get_audit(self, past_hours: int = 5, search_filters: list = []):
        """Get audit logs from open search."""
        return self._get_index(index="audit-ms*", past_hours=past_hours, search_filters=search_filters)

    def get_audit_node(self, past_hours: int = 5, search_filters: list = []):
        """Get audit logs node from open search."""
        return self._get_index(index="audit-node*", past_hours=past_hours, search_filters=search_filters)

    def get_filebeat(self, past_hours: int = 5, search_filters: list = []):
        """Get filebeat logs from open search."""
        return self._get_index(index="filebeat*", past_hours=past_hours, search_filters=search_filters)

    def get_nerve(self, past_hours: int = 5, search_filters: list = []):
        """Get nerve logs from open search."""
        return self._get_index(index="nerve-ms-*", past_hours=past_hours, search_filters=search_filters)

    def get_fluentbit(self, past_hours: int = 5, search_filters: list = []):
        """Get filebeat logs from open search."""
        return self._get_index(index="docker-log*", past_hours=past_hours, search_filters=search_filters)

    def get_audit_docker(self, past_hours: int = 5, search_filters: list = []):
        """Get audit logs node from open search."""
        return self._get_index(
            index="audit-docker-log*", past_hours=past_hours, search_filters=search_filters
        )

    def filter_audit_hits(self, past_hours=5, node=False, docker=False, **kwargs):
        """Filter hits of audit log matching different keywords.

        >>> kwargs = {"Event ID": 1012}
        >>> opensearch.filter_audit_hits(index=0, kwargs)
        """
        if node:
            response_data = self.get_audit_node(past_hours)
        elif docker:
            response_data = self.get_audit_docker(past_hours)
        else:
            response_data = self.get_audit(past_hours)

        hits_indexs = [hits["_source"] for hits in response_data["rawResponse"]["hits"]["hits"]]

        matching_hits = []

        for hits_index in hits_indexs:
            add_match = True
            for name, value in kwargs.items():
                if hits_index.get(name) != value:
                    add_match = False
            if add_match:
                matching_hits.append(hits_index)
        return matching_hits

    def filter_docker_logs(self, past_hours=5, container_name=None, **kwargs):
        """Filter hits of filebeats log matching different keywords.

        >>> kwargs = {"partial_message": "partial text of the message"}
        >>> opensearch.filter_docker_logs(past_hours=5, container_name="my_container", **kwargs)
        """
        if self.ms.version_smaller_than("2.10.0"):
            response_data = self.get_filebeat(past_hours)
        else:
            response_data = self.get_fluentbit(past_hours)

        hits = response_data["rawResponse"]["hits"]["hits"]
        matching_hits = []

        for hit in hits:
            hit_source = hit["_source"]

            if self.ms.version_smaller_than("2.10.0"):
                container = hit_source.get("container", {})
                message = hit_source.get("message", "")
            else:
                container = hit_source.get("container_name", {})
                message = hit_source.get("log", "")

            if isinstance(container, dict):
                if container_name and container.get("name") != container_name:
                    continue
            elif container_name and container != container_name:
                continue

            partial_message = kwargs.get("partial_message", "")

            # Check if the partial message is contained within the hit message
            if partial_message and partial_message in message:
                add_match = True
                for name, value in kwargs.items():
                    if name != "partial_message" and hit_source.get(name) != value:
                        add_match = False
                        break
                if add_match:
                    matching_hits.append(hit_source)

        return matching_hits

    def messages_audit(self, message_level: str = "", past_hours: int = 5, search_filters: list = []):
        """Get messages from audit logs.

        message_level str, optional:
            one of "info", "warn", "error"
        """
        all_filters = deepcopy(search_filters)
        if message_level:
            all_filters.append(self.create_filter_matchphrase("message", f"'level':'{message_level}'"))
        response_data = self.get_audit(past_hours, all_filters)
        return [msg["_source"] for msg in response_data["rawResponse"]["hits"]["hits"]]

    def messages_filebeat(self, severity_level: str = "", past_hours: int = 5, search_filters: list = []):
        """Get messages from filebeat logs.

        severtiy_level: one of ["Informational","Error","Warning"].
        """
        all_filters = deepcopy(search_filters)
        if severity_level:
            all_filters.append(
                self.create_filter_matchphrase("syslog.severity_label", severity_level.title()),
            )
        response_data = self.get_filebeat(past_hours, all_filters)
        return [msg["_source"] for msg in response_data["rawResponse"]["hits"]["hits"]]

    def messages_nerve(self, message_level: str = "", past_hours: int = 5, search_filters: list = []):
        """Get messages from nerve logs."""
        all_filters = deepcopy(search_filters)
        if message_level:
            all_filters.append(self.create_filter_matchphrase("message", f"'level':'{message_level}'"))
        response_data = self.get_nerve(past_hours, all_filters)
        return [json.loads(msg["_source"]["message"]) for msg in response_data["rawResponse"]["hits"]["hits"]]

    def create_index(self, index_name):
        """Create a new OpenSearch Index."""
        payload = {
            "data": {
                "index": index_name,
                "body": {
                    "settings": {
                        "index.number_of_shards": 1,
                        "index.number_of_replicas": 1,
                        "index.refresh_interval": "1s",
                    },
                    "mappings": {"properties": {}},
                },
            },
            "endpoint": "indices.create",
        }

        return self.__post_payload("/opensearch/api/ism/apiCaller", payload)

    def delete_index(self, index_name):
        """Delete an OpenSearch Index."""
        payload = {"data": {"index": index_name}, "endpoint": "indices.delete"}

        return self.__post_payload("/opensearch/api/ism/apiCaller", payload)
