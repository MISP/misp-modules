"""vt_graph_parser.importers.pymisp_response.

This modules provides a graph importer method for MISP event by using the
response payload giving by MISP API directly.
"""

from vt_graph_parser.helpers.parsers import parse_pymisp_response
from vt_graph_parser.importers.base import import_misp_graph


def from_pymisp_response(
    payload,
    vt_api_key,
    fetch_information=True,
    private=False,
    fetch_vt_enterprise=False,
    user_editors=None,
    user_viewers=None,
    group_editors=None,
    group_viewers=None,
    use_vt_to_connect_the_graph=False,
    max_api_quotas=1000,
    max_search_depth=3,
    expand_node_one_level=False,
):
    """Import VirusTotal Graph from MISP JSON file.

    Args:
      payload (dict): dictionary which contains the request payload.
      vt_api_key (str): VT API Key.
      fetch_information (bool, optional): whether the script will fetch
        information for added nodes in VT. Defaults to True.
      name (str, optional): graph title. Defaults to "".
      private (bool, optional): True for private graphs. You need to have
        Private Graph premium features enabled in your subscription. Defaults
        to False.
      fetch_vt_enterprise (bool, optional): if True, the graph will search any
        available information using VirusTotal Intelligence for the node if there
        is no normal information for it. Defaults to False.
      user_editors ([str], optional): usernames that can edit the graph.
        Defaults to None.
      user_viewers ([str], optional): usernames that can view the graph.
        Defaults to None.
      group_editors ([str], optional): groups that can edit the graph.
        Defaults to None.
      group_viewers ([str], optional): groups that can view the graph.
        Defaults to None.
      use_vt_to_connect_the_graph (bool, optional): if True, graph nodes will
        be linked using VirusTotal API. Otherwise, the links will be generated
        using production rules based on MISP attributes order. Defaults to
        False.
      max_api_quotas (int, optional): maximum number of api quotas that could
        be consumed to resolve graph using VirusTotal API. Defaults to 20000.
      max_search_depth (int, optional): max search depth to explore
        relationship between nodes when use_vt_to_connect_the_graph is True.
        Defaults to 3.
      expand_one_level (bool, optional): expand entire graph one level.
        Defaults to False.

    If use_vt_to_connect_the_graph is True, it will take some time to compute
    graph.

    Raises:
      LoaderError: if JSON file is invalid.

    Returns:
      [vt_graph_api.graph.VTGraph: the imported graph].
    """
    graphs = []
    for event_payload in payload["data"]:
        misp_attrs, graph_id = parse_pymisp_response(event_payload)
        name = "Graph created from MISP event"
        graph = import_misp_graph(
            misp_attrs,
            graph_id,
            vt_api_key,
            fetch_information,
            name,
            private,
            fetch_vt_enterprise,
            user_editors,
            user_viewers,
            group_editors,
            group_viewers,
            use_vt_to_connect_the_graph,
            max_api_quotas,
            max_search_depth,
        )
        if expand_node_one_level:
            graph.expand_n_level(1)
        graphs.append(graph)
    return graphs
