[back (nerve_lib)](./index.md)

Module nerve_lib.manage_open_search
===================================
Manage OpenSearch releated function on MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSOpenSearch
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     opensearch = MSOpenSearch(ms_handle)
    >>>     opensearch.get_audit()
    <dict of audit request>

Classes
-------

`MSOpenSearch(ms_handle)`
:   Create opensearch requets.
    
    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Static methods

    `create_filter_matchphrase(field, phrase)`
    :   Define which field should be filtered by a phrase.

    `create_search_bestfield(keyword)`
    :   Search for simple keyword.
        
        If keyword contains multiple works, each word will create a match.

    `create_search_multimatch_phrase(phrase)`
    :   Search for keyword(s) phrase.
        
        Phrase can have multiple works, result will contain matches of the complete phrase.

    ### Methods

    `create_index(self, index_name)`
    :   Create a new OpenSearch Index.

    `delete_index(self, index_name)`
    :   Delete an OpenSearch Index.

    `filter_audit_hits(self, past_hours=5, node=False, docker=False, **kwargs)`
    :   Filter hits of audit log matching different keywords.
        
        >>> kwargs = {"Event ID": 1012}
        >>> opensearch.filter_audit_hits(index=0, kwargs)

    `filter_docker_logs(self, past_hours=5, container_name=None, **kwargs)`
    :   Filter hits of filebeats log matching different keywords.
        
        >>> kwargs = {"partial_message": "partial text of the message"}
        >>> opensearch.filter_docker_logs(past_hours=5, container_name="my_container", **kwargs)

    `get_audit(self, past_hours: int = 5, search_filters: list = [])`
    :   Get audit logs from open search.

    `get_audit_docker(self, past_hours: int = 5, search_filters: list = [])`
    :   Get audit logs node from open search.

    `get_audit_node(self, past_hours: int = 5, search_filters: list = [])`
    :   Get audit logs node from open search.

    `get_filebeat(self, past_hours: int = 5, search_filters: list = [])`
    :   Get filebeat logs from open search.

    `get_fluentbit(self, past_hours: int = 5, search_filters: list = [])`
    :   Get filebeat logs from open search.

    `get_nerve(self, past_hours: int = 5, search_filters: list = [])`
    :   Get nerve logs from open search.

    `messages_audit(self, message_level: str = '', past_hours: int = 5, search_filters: list = [])`
    :   Get messages from audit logs.
        
        message_level str, optional:
            one of "info", "warn", "error"

    `messages_filebeat(self, severity_level: str = '', past_hours: int = 5, search_filters: list = [])`
    :   Get messages from filebeat logs.
        
        severtiy_level: one of ["Informational","Error","Warning"].

    `messages_nerve(self, message_level: str = '', past_hours: int = 5, search_filters: list = [])`
    :   Get messages from nerve logs.