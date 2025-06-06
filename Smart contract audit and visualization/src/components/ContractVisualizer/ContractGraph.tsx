import React, { useEffect, useRef } from 'react';
import { ForceGraph2D } from 'react-force-graph';

interface ContractNode {
  id: string;
  name: string;
  type: 'function' | 'event' | 'variable';
}

interface ContractLink {
  source: string;
  target: string;
  type: 'calls' | 'emits' | 'modifies';
}

interface ContractGraphProps {
  nodes: ContractNode[];
  links: ContractLink[];
}

export const ContractGraph: React.FC<ContractGraphProps> = ({ nodes, links }) => {
  const graphRef = useRef<any>();

  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.d3Force('charge').strength(-100);
    }
  }, []);

  return (
    <ForceGraph2D
      ref={graphRef}
      graphData={{ nodes, links }}
      nodeAutoColorBy="type"
      nodeLabel="name"
      linkDirectionalArrowLength={3}
      linkDirectionalArrowRelPos={1}
    />
  );
};