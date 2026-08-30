import React from 'react';
import ReactECharts from 'echarts-for-react';
import dayjs from 'dayjs';

interface CertExpiry {
  id: string;
  common_name: string;
  not_after: string;
  not_before: string;
  status: string;
}

interface Props {
  data: CertExpiry[];
  days?: number;
  height?: number;
}

export default function ExpiryGantt({ data, days = 90, height = 300 }: Props) {
  if (!data.length) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8c8c8c' }}>No certificates expiring in the next {days} days</div>;
  }

  const now = dayjs();
  const endDate = now.add(days, 'day');

  const option = {
    tooltip: {
      trigger: 'item',
      formatter: (params: any) => {
        const cert = data[params.dataIndex];
        if (!cert) return '';
        const expDate = dayjs(cert.not_after);
        const daysLeft = expDate.diff(now, 'day');
        return `<strong>${cert.common_name}</strong><br/>
          Expires: ${expDate.format('YYYY-MM-DD')}<br/>
          Days left: <b style="color:${daysLeft < 7 ? '#ff4d4f' : daysLeft < 30 ? '#faad14' : '#52c41a'}">${daysLeft}</b>`;
      },
    },
    grid: {
      left: 200,
      right: 40,
      top: 10,
      bottom: 30,
    },
    xAxis: {
      type: 'time',
      min: now.valueOf(),
      max: endDate.valueOf(),
      axisLabel: {
        formatter: (value: number) => dayjs(value).format('MMM D'),
      },
    },
    yAxis: {
      type: 'category',
      data: data.map((c) => c.common_name || 'Unknown'),
      axisLabel: {
        width: 180,
        overflow: 'truncate',
        fontSize: 11,
      },
      inverse: true,
    },
    series: [
      {
        type: 'custom',
        renderItem: (_params: any, api: any) => {
          const categoryIndex = api.value(0);
          const start = api.coord([now.valueOf(), categoryIndex]);
          const end = api.coord([dayjs(data[categoryIndex]?.not_after).valueOf(), categoryIndex]);
          const height = api.size([0, 1])[1] * 0.5;

          const cert = data[categoryIndex];
          const daysLeft = dayjs(cert?.not_after).diff(now, 'day');
          const color = cert?.status === 'expired' || daysLeft < 0 ? '#ff4d4f'
            : daysLeft <= 7 ? '#ff4d4f'
            : daysLeft <= 30 ? '#faad14'
            : daysLeft <= 60 ? '#1677ff'
            : '#52c41a';

          return {
            type: 'rect',
            shape: {
              x: start[0],
              y: end[1] - height / 2,
              width: Math.max(end[0] - start[0], 4),
              height,
            },
            style: {
              fill: color,
              borderRadius: 3,
            },
          };
        },
        data: data.map((_d, i) => [i]),
        encode: {
          x: [1],
          y: [0],
        },
      },
    ],
  };

  return <ReactECharts option={option} style={{ height }} />;
}
