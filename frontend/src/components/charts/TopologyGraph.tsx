import React from 'react';
import ReactECharts from 'echarts-for-react';

interface Datacenter {
  id: string;
  name: string;
  code: string;
  location?: string;
  is_active: boolean;
  certificate_counts: { active: number; expired: number; total: number };
  authorities: Array<{
    id: string;
    name: string;
    ca_type: string;
    health_status: string;
  }>;
  agents: Array<{
    id: string;
    name: string;
    status: string;
  }>;
}

interface Props {
  datacenters: Datacenter[];
  height?: number;
}

const CA_TYPE_COLORS: Record<string, string> = {
  aws_acm: '#ff9900',
  azure_keyvault: '#0078d4',
  adcs: '#00a4ef',
};

const HEALTH_COLORS: Record<string, string> = {
  healthy: '#52c41a',
  degraded: '#faad14',
  unhealthy: '#ff4d4f',
  unknown: '#d9d9d9',
};

export default function TopologyGraph({ datacenters, height = 400 }: Props) {
  if (!datacenters.length) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8c8c8c' }}>No datacenters configured</div>;
  }

  // Build a force-directed graph
  const nodes: Array<{
    id: string;
    name: string;
    symbolSize: number;
    category: number;
    itemStyle?: { color: string };
    label?: { show: boolean };
  }> = [];

  const links: Array<{ source: string; target: string }> = [];
  const categories = [
    { name: 'Datacenter' },
    { name: 'CA (AWS)' },
    { name: 'CA (Azure)' },
    { name: 'CA (AD CS)' },
    { name: 'Agent' },
  ];

  datacenters.forEach((dc) => {
    const dcNodeId = `dc-${dc.id}`;
    nodes.push({
      id: dcNodeId,
      name: dc.name,
      symbolSize: 45,
      category: 0,
      label: { show: true },
    });

    dc.authorities.forEach((ca) => {
      const caNodeId = `ca-${ca.id}`;
      const catIdx = ca.ca_type === 'aws_acm' ? 1 : ca.ca_type === 'azure_keyvault' ? 2 : 3;
      nodes.push({
        id: caNodeId,
        name: ca.name,
        symbolSize: 25,
        category: catIdx,
        itemStyle: { color: HEALTH_COLORS[ca.health_status] || CA_TYPE_COLORS[ca.ca_type] || '#666' },
      });
      links.push({ source: dcNodeId, target: caNodeId });
    });

    dc.agents.forEach((agent) => {
      const agentNodeId = `agent-${agent.id}`;
      nodes.push({
        id: agentNodeId,
        name: agent.name,
        symbolSize: 18,
        category: 4,
        itemStyle: { color: agent.status === 'online' ? '#52c41a' : '#ff4d4f' },
      });
      links.push({ source: dcNodeId, target: agentNodeId });
    });
  });

  const option = {
    tooltip: {
      formatter: (params: any) => {
        if (params.dataType === 'node') {
          return `<strong>${params.name}</strong><br/>Category: ${categories[params.data.category]?.name || 'Unknown'}`;
        }
        return `${params.data.source} → ${params.data.target}`;
      },
    },
    legend: {
      data: categories.map((c) => c.name),
      bottom: 0,
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        force: {
          repulsion: 300,
          edgeLength: [100, 200],
          gravity: 0.15,
        },
        roam: true,
        draggable: true,
        data: nodes.map((n) => ({ ...n, category: categories[n.category]?.name })),
        links,
        categories,
        label: {
          show: true,
          position: 'right',
          fontSize: 10,
        },
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: [0, 6],
        lineStyle: {
          color: '#d9d9d9',
          curveness: 0.2,
        },
      },
    ],
  };

  return <ReactECharts option={option} style={{ height }} />;
}
