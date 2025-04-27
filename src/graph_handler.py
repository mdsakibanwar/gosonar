import pyintergraph
import graph_tool.all as gt
import networkx as nx
from loguru import logger

class GraphHandler():

    def __init__(self, nx_graph) -> None:
        self._nx_graph = nx_graph
        self._inter_graph = pyintergraph.InterGraph.from_networkx(self._nx_graph)
        self._cycles = None
        logger.debug(
            f"Converted graph to intergraph nodes: {self._nx_graph.number_of_nodes()}, edges: {self._nx_graph.number_of_edges()}"
        )
        self._gt_graph = self._inter_graph.to_graph_tool()
        logger.debug("Converted intergraph to gt graph")

    # Caution: iterator is being reused
    def generate_cycles(self):
        if self._cycles is None:
            self._cycles = gt.all_circuits(self._gt_graph, False)
        else:
            raise Exception("Iterator is being reused")

    def generate_cycles_in_cg(self):
        logger.debug("Generating all cycles :o")
        self.generate_cycles()
        logger.debug(f"GT Found cycles in graph")
        for cycle in self._cycles:
            cycle_list = cycle.tolist()
            yield list(map(lambda x: self.map_to_nx(x), cycle_list))

    def count_cycles(self):
        logger.debug("Counting all circuits :o")
        self.generate_cycles()
        count = 0
        for cycle in self._cycles:
            count += 1
            print(count, end="\r")
        return count

    def map_to_gt(self, addr):
        return self._inter_graph.label_map[addr] if addr in self._inter_graph.label_map else None

    def map_to_nx(self, addr):
        return self._inter_graph.node_labels[addr] if addr in self._inter_graph.node_labels else None

    def get_targeted_cycle(self, target):
        logger.debug(f"Getting targeted cycle with address@{hex(target)}")
        self.generate_cycles()
        target_mapped = self.map_to_gt(target)
        for cycle in self._cycles:
            if target_mapped in cycle:
                cycle_list = cycle.tolist()
                return list(map(lambda x: self.map_to_nx(x), cycle_list))            

    def find_shortest_path_in_cg(self, source, target):
        path = []
        m_source, m_target = self.map_to_gt(source), self.map_to_gt(target)
        if m_source and m_target:
            vertices, edges = gt.shortest_path(self._gt_graph, m_source, m_target)
            for vertex in vertices:
                if isinstance(vertex, gt.Vertex):
                    path.append(self.map_to_nx(self._gt_graph.vertex_index[vertex]))
                else:
                    path.append(self.map_to_nx(vertex))
        return path
