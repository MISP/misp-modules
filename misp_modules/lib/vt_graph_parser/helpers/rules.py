"""vt_graph_parser.helpers.rules.

This module provides rules that helps MISP importers to connect MISP attributes
between them using VirusTotal relationship. Check all available relationship
here:

- File: https://docs.virustotal.com/reference/files#relationships
- URL: https://docs.virustotal.com/reference/url-object#relationships
- Domain: https://docs.virustotal.com/reference/domains-object#relationships
- IP: https://docs.virustotal.com/reference/ip-object#relationships
"""

import abc


class MispEventRule(object):
    """Rules for MISP event nodes connection object wrapper."""

    def __init__(self, last_rule=None, node=None):
        """Create a MispEventRule instance.

        MispEventRule is a collection of rules that can infer the relationships
        between nodes from MISP events.

        Args:
          last_rule (MispEventRule): previous rule.
          node (Node): actual node.
        """
        self.last_rule = last_rule
        self.node = node
        self.relation_event = {
            "ip_address": self.__ip_transition,
            "url": self.__url_transition,
            "domain": self.__domain_transition,
            "file": self.__file_transition,
        }

    def get_last_different_rule(self):
        """Search the last rule whose event was different from actual.

        Returns:
          MispEventRule: the last different rule.
        """
        if not isinstance(self, self.last_rule.__class__):
            return self.last_rule
        else:
            return self.last_rule.get_last_different_rule()

    def resolve_relation(self, graph, node, misp_category):
        """Try to infer a relationship between two nodes.

        This method is based on a non-deterministic finite automaton for
        this reason the future rule only depends on the actual rule and the input
        node.

        For example if the actual rule is a MISPEventDomainRule and the given node
        is an ip_address node, the connection type between them will be
        `resolutions` and the this rule will transit to MISPEventIPRule.

        Args:
          graph (VTGraph): graph to be computed.
          node (Node): the node to be linked.
          misp_category: (str): MISP category of the given node.

        Returns:
          MispEventRule: the transited rule.
        """
        if node.node_type in self.relation_event:
            return self.relation_event[node.node_type](graph, node, misp_category)
        else:
            return self.manual_link(graph, node)

    def manual_link(self, graph, node):
        """Creates a manual link between self.node and the given node.

        We accept MISP types that VirusTotal does not know how to link, so we create
        a end to end relationship instead of create an unknown relationship node.

        Args:
          graph (VTGraph): graph to be computed.
          node (Node): the node to be linked.

        Returns:
          MispEventRule: the transited rule.
        """
        graph.add_link(self.node.node_id, node.node_id, "manual")
        return self

    @abc.abstractmethod
    def __file_transition(self, graph, node, misp_category):
        """Make a new transition due to file attribute event.

        Args:
          graph (VTGraph): graph to be computed.
          node (Node): the node to be linked.
          misp_category: (str): MISP category of the given node.

        Returns:
          MispEventRule: the transited rule.
        """
        pass

    @abc.abstractmethod
    def __ip_transition(self, graph, node, misp_category):
        """Make a new transition due to ip attribute event.

        Args:
          graph (VTGraph): graph to be computed.
          node (Node): the node to be linked.
          misp_category: (str): MISP category of the given node.

        Returns:
          MispEventRule: the transited rule.
        """
        pass

    @abc.abstractmethod
    def __url_transition(self, graph, node, misp_category):
        """Make a new transition due to url attribute event.

        Args:
          graph (VTGraph): graph to be computed.
          node (Node): the node to be linked.
          misp_category: (str): MISP category of the given node.

        Returns:
          MispEventRule: the transited rule.
        """
        pass

    @abc.abstractmethod
    def __domain_transition(self, graph, node, misp_category):
        """Make a new transition due to domain attribute event.

        Args:
          graph (VTGraph): graph to be computed.
          node (Node): the node to be linked.
          misp_category: (str): MISP category of the given node.

        Returns:
          MispEventRule: the transited rule.
        """
        pass


class MispEventURLRule(MispEventRule):
    """Rule for URL event."""

    def __init__(self, last_rule=None, node=None):
        super(MispEventURLRule, self).__init__(last_rule, node)
        self.relation_event = {
            "ip_address": self.__ip_transition,
            "url": self.__url_transition,
            "domain": self.__domain_transition,
            "file": self.__file_transition,
        }

    def __file_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "downloaded_files")
        return MispEventFileRule(self, node)

    def __ip_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "contacted_ips")
        return MispEventIPRule(self, node)

    def __url_transition(self, graph, node, misp_category):
        suitable_rule = self.get_last_different_rule()
        if not isinstance(suitable_rule, MispEventInitialRule):
            return suitable_rule.resolve_relation(graph, node, misp_category)
        else:
            return MispEventURLRule(self, node)

    def __domain_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "contacted_domains")
        return MispEventDomainRule(self, node)


class MispEventIPRule(MispEventRule):
    """Rule for IP event."""

    def __init__(self, last_rule=None, node=None):
        super(MispEventIPRule, self).__init__(last_rule, node)
        self.relation_event = {
            "ip_address": self.__ip_transition,
            "url": self.__url_transition,
            "domain": self.__domain_transition,
            "file": self.__file_transition,
        }

    def __file_transition(self, graph, node, misp_category):
        connection_type = "communicating_files"
        if misp_category == "Artifacts dropped":
            connection_type = "downloaded_files"
        graph.add_link(self.node.node_id, node.node_id, connection_type)
        return MispEventFileRule(self, node)

    def __ip_transition(self, graph, node, misp_category):
        suitable_rule = self.get_last_different_rule()
        if not isinstance(suitable_rule, MispEventInitialRule):
            return suitable_rule.resolve_relation(graph, node, misp_category)
        else:
            return MispEventIPRule(self, node)

    def __url_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "urls")
        return MispEventURLRule(self, node)

    def __domain_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "resolutions")
        return MispEventDomainRule(self, node)


class MispEventDomainRule(MispEventRule):
    """Rule for domain event."""

    def __init__(self, last_rule=None, node=None):
        super(MispEventDomainRule, self).__init__(last_rule, node)
        self.relation_event = {
            "ip_address": self.__ip_transition,
            "url": self.__url_transition,
            "domain": self.__domain_transition,
            "file": self.__file_transition,
        }

    def __file_transition(self, graph, node, misp_category):
        connection_type = "communicating_files"
        if misp_category == "Artifacts dropped":
            connection_type = "downloaded_files"
        graph.add_link(self.node.node_id, node.node_id, connection_type)
        return MispEventFileRule(self, node)

    def __ip_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "resolutions")
        return MispEventIPRule(self, node)

    def __url_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "urls")
        return MispEventURLRule(self, node)

    def __domain_transition(self, graph, node, misp_category):
        suitable_rule = self.get_last_different_rule()
        if not isinstance(suitable_rule, MispEventInitialRule):
            return suitable_rule.resolve_relation(graph, node, misp_category)
        else:
            graph.add_link(self.node.node_id, node.node_id, "siblings")
            return MispEventDomainRule(self, node)


class MispEventFileRule(MispEventRule):
    """Rule for File event."""

    def __init__(self, last_rule=None, node=None):
        super(MispEventFileRule, self).__init__(last_rule, node)
        self.relation_event = {
            "ip_address": self.__ip_transition,
            "url": self.__url_transition,
            "domain": self.__domain_transition,
            "file": self.__file_transition,
        }

    def __file_transition(self, graph, node, misp_category):
        suitable_rule = self.get_last_different_rule()
        if not isinstance(suitable_rule, MispEventInitialRule):
            return suitable_rule.resolve_relation(graph, node, misp_category)
        else:
            return MispEventFileRule(self, node)

    def __ip_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "contacted_ips")
        return MispEventIPRule(self, node)

    def __url_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "contacted_urls")
        return MispEventURLRule(self, node)

    def __domain_transition(self, graph, node, misp_category):
        graph.add_link(self.node.node_id, node.node_id, "contacted_domains")
        return MispEventDomainRule(self, node)


class MispEventInitialRule(MispEventRule):
    """Initial rule."""

    def __init__(self, last_rule=None, node=None):
        super(MispEventInitialRule, self).__init__(last_rule, node)
        self.relation_event = {
            "ip_address": self.__ip_transition,
            "url": self.__url_transition,
            "domain": self.__domain_transition,
            "file": self.__file_transition,
        }

    def __file_transition(self, graph, node, misp_category):
        return MispEventFileRule(self, node)

    def __ip_transition(self, graph, node, misp_category):
        return MispEventIPRule(self, node)

    def __url_transition(self, graph, node, misp_category):
        return MispEventURLRule(self, node)

    def __domain_transition(self, graph, node, misp_category):
        return MispEventDomainRule(self, node)
