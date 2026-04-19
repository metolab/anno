import { Card, Col, Row, Statistic, Typography } from "antd";
import { useEffect, useState } from "react";
import { fetchStats, formatBytes, StatsDto } from "../api";

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsDto | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const s = await fetchStats();
        if (!cancelled) setStats(s);
      } catch {
        if (!cancelled) setStats(null);
      }
    };
    load();
    const timer = setInterval(load, 10_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div>
      <Typography.Title level={3}>Dashboard</Typography.Title>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic
              title="Control Port"
              value={stats?.control_port ?? 0}
              groupSeparator=""
              suffix={
                stats?.control_port != null ? (
                  <Typography.Text
                    copyable={{ text: String(stats.control_port) }}
                    style={{ fontSize: 14 }}
                  />
                ) : null
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic title="Clients Online" value={stats?.clients_online ?? 0} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic title="Clients Total" value={stats?.clients_total ?? 0} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic title="Mappings" value={stats?.mappings_total ?? 0} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic title="Active Sessions" value={stats?.sessions_active ?? 0} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic
              title="Bytes Transferred ↑"
              value={formatBytes(stats?.bytes_up_total ?? 0)}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic
              title="Bytes Transferred ↓"
              value={formatBytes(stats?.bytes_down_total ?? 0)}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic
              title="Queue Drops"
              value={stats?.queue_drops_total ?? 0}
              valueStyle={
                (stats?.queue_drops_total ?? 0) > 0 ? { color: "#cf1322" } : undefined
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic title="TCP Sessions" value={stats?.sessions_tcp ?? 0} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={8}>
          <Card>
            <Statistic title="UDP Sessions" value={stats?.sessions_udp ?? 0} />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
