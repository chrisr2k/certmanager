import React from 'react';
import ReactECharts from 'echarts-for-react';

interface ScanPoint {
  time: string;
  success: number;
  failed: number;
  running: number;
}

interface Props {
  data: ScanPoint[];
  height?: number;
}

export default function HealthTimeline({ data, height = 250 }: Props) {
  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
    },
    legend: {
      data: ['Success', 'Failed', 'Running'],
      bottom: 0,
    },
    grid: {
      left: 40,
      right: 20,
      top: 20,
      bottom: 40,
    },
    xAxis: {
      type: 'category',
      data: data.map((d) => d.time.slice(11, 16)), // Show HH:MM
      axisLabel: { rotate: 45, fontSize: 10 },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
    },
    series: [
      {
        name: 'Success',
        type: 'bar',
        stack: 'total',
        data: data.map((d) => d.success),
        itemStyle: { color: '#52c41a' },
        emphasis: { focus: 'series' },
      },
      {
        name: 'Failed',
        type: 'bar',
        stack: 'total',
        data: data.map((d) => d.failed),
        itemStyle: { color: '#ff4d4f' },
        emphasis: { focus: 'series' },
      },
      {
        name: 'Running',
        type: 'bar',
        stack: 'total',
        data: data.map((d) => d.running),
        itemStyle: { color: '#1677ff' },
        emphasis: { focus: 'series' },
      },
    ],
  };

  if (!data.length) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8c8c8c' }}>No scan data in the last 24 hours</div>;
  }

  return <ReactECharts option={option} style={{ height }} />;
}
