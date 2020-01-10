"""vt_graph_parser.importers.base.

This module provides a common method to import graph from misp attributes.
"""


import vt_graph_api
from vt_graph_parser.helpers.rules import MispEventInitialRule


def import_misp_graph(
        misp_attributes, graph_id, vt_api_key, fetch_information, name,
        private, fetch_vt_enterprise, user_editors, user_viewers, group_editors,
        group_viewers, use_vt_to_connect_the_graph, max_api_quotas,
        max_search_depth):
    """Import VirusTotal Graph from MISP.

    Args:
      misp_attributes  ([MispAttribute]): list with the MISP attributes which
        will be added to the returned graph.
      graph_id: if supplied, the graph will be loaded instead of compute it again.
      vt_api_key (str): VT API Key.
      fetch_information (bool): whether the script will fetch
        information for added nodes in VT. Defaults to True.
      name (str): graph title. Defaults to "".
      private (bool): True for private graphs. You need to have
        Private Graph premium features enabled in your subscription. Defaults
        to False.
      fetch_vt_enterprise (bool, optional): if True, the graph will search any
        available information using VirusTotal Intelligence for the node if there
        is no normal information for it. Defaults to False.
      user_editors ([str]): usernames that can edit the graph.
        Defaults to None.
      user_viewers ([str]): usernames that can view the graph.
        Defaults to None.
      group_editors ([str]): groups that can edit the graph.
        Defaults to None.
      group_viewers ([str]): groups that can view the graph.
        Defaults to None.
      use_vt_to_connect_the_graph (bool): if True, graph nodes will
        be linked using VirusTotal API. Otherwise, the links will be generated
        using production rules based on MISP attributes order. Defaults to
        False.
      max_api_quotas (int): maximum number of api quotas that could
        be consumed to resolve graph using VirusTotal API. Defaults to 20000.
      max_search_depth (int, optional): max search depth to explore
        relationship between nodes when use_vt_to_connect_the_graph is True.
        Defaults to 3.

    If use_vt_to_connect_the_graph is True, it will take some time to compute
    graph.

    Returns:
      vt_graph_api.graph.VTGraph: the imported graph.
    """

    rule = MispEventInitialRule()

    # Check if the event has been already computed in VirusTotal Graph. Otherwise
    # a new graph will be created.
    if not graph_id:
        graph = vt_graph_api.VTGraph(
            api_key=vt_api_key, name=name, private=private,
            user_editors=user_editors, user_viewers=user_viewers,
            group_editors=group_editors, group_viewers=group_viewers)
    else:
        graph = vt_graph_api.VTGraph.load_graph(graph_id, vt_api_key)

    attributes_to_add = [attr for attr in misp_attributes
                         if not graph.has_node(attr.value)]

    total_expandable_attrs = max(sum(
        1 for attr in attributes_to_add
        if attr.type in vt_graph_api.Node.SUPPORTED_NODE_TYPES),
        1)

    max_quotas_per_search = max(
        int(max_api_quotas / total_expandable_attrs), 1)

    previous_node_id = ""
    for attr in attributes_to_add:
        # Add the current attr as node to the graph.
        added_node = graph.add_node(
            attr.value, attr.type, fetch_information, fetch_vt_enterprise,
            attr.label)
        # If use_vt_to_connect_the_grap is True the nodes will be connected using
        # VT API.
        if use_vt_to_connect_the_graph:
            if (attr.type not in vt_graph_api.Node.SUPPORTED_NODE_TYPES and previous_node_id):
                graph.add_link(previous_node_id, attr.value, "manual")
            else:
                graph.connect_with_graph(
                    attr.value, max_quotas_per_search, max_search_depth,
                    fetch_info_collected_nodes=fetch_information)
        else:
            rule = rule.resolve_relation(graph, added_node, attr.category)

    return graph
