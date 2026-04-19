import {
  App,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CopyOutlined,
  DeleteOutlined,
  DisconnectOutlined,
  KeyOutlined,
  PlusOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  addMapping,
  createRegistryEntry,
  deleteMapping,
  deleteRegistryEntry,
  disconnectClient,
  fetchClients,
  fetchRegistry,
  formatBytes,
  regenerateRegistryKey,
  updateRegistryEntry,
  type ClientDto,
  type MappingDto,
  type RegistryEntryDto,
} from "../api";

// ============================================================================
// Unified client view
// ============================================================================
//
// The page joins the persisted registry (source of truth for name/key/
// description) with the runtime client directory (source of truth for
// online status, remote peer, active sessions). Persisted port mappings
// are surfaced even when the client is offline because the server now
// pre-materialises a ClientRecord for every registry entry.

type UnifiedRow = {
  // registry-derived
  name: string;
  key: string;
  description?: string | null;
  createdAt: number;

  // runtime-derived (null/undefined when offline or when the client has
  // never connected after startup)
  clientId?: number;
  status: "online" | "offline";
  remoteAddr?: string | null;
  httpProxyPort?: number | null;
  mappings: MappingDto[];
};

function joinRegistryWithClients(
  entries: RegistryEntryDto[],
  clients: ClientDto[],
): UnifiedRow[] {
  const byName = new Map<string, ClientDto>();
  for (const c of clients) byName.set(c.name, c);

  return entries.map((e) => {
    const c = byName.get(e.name);
    return {
      name: e.name,
      key: e.key,
      description: e.description,
      createdAt: e.created_at,
      clientId: c?.id,
      status: c?.status === "online" ? "online" : "offline",
      remoteAddr: c?.remote_addr ?? null,
      httpProxyPort: c?.http_proxy_port ?? null,
      mappings: c?.mappings ?? [],
    };
  });
}

export default function ClientsPage() {
  const { message, modal } = App.useApp();

  const [rows, setRows] = useState<UnifiedRow[]>([]);
  const [loading, setLoading] = useState(false);

  // create-entry modal
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm] = Form.useForm();

  // edit-description modal
  const [editRow, setEditRow] = useState<UnifiedRow | null>(null);
  const [editForm] = Form.useForm();

  // add-mapping modal
  const [mappingModalOpen, setMappingModalOpen] = useState(false);
  const [mappingTargetClientId, setMappingTargetClientId] = useState<
    number | null
  >(null);
  const [mappingForm] = Form.useForm();

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const [entries, clients] = await Promise.all([
        fetchRegistry(),
        fetchClients(),
      ]);
      setRows(joinRegistryWithClients(entries, clients));
    } catch {
      message.error("加载客户端数据失败");
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void reload();
    // Per-mapping traffic counters need periodic refresh to be useful;
    // align with the Dashboard's polling cadence (5s here, finer-grained
    // than the dashboard so traffic feels live in the mapping table).
    const timer = setInterval(() => {
      void reload();
    }, 5_000);
    return () => clearInterval(timer);
  }, [reload]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(
      () => message.success("已复制到剪贴板"),
      () => message.error("复制失败"),
    );
  };

  const handleCreate = async () => {
    const v = await createForm.validateFields();
    try {
      await createRegistryEntry({
        name: v.name,
        description: v.description || undefined,
      });
      message.success("客户端条目已创建");
      setCreateOpen(false);
      createForm.resetFields();
      await reload();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } };
      message.error(err.response?.data?.message ?? "创建失败");
    }
  };

  const handleEdit = async () => {
    if (!editRow) return;
    const v = await editForm.validateFields();
    try {
      await updateRegistryEntry(editRow.name, {
        description: v.description || null,
      });
      message.success("已更新");
      setEditRow(null);
      await reload();
    } catch {
      message.error("更新失败");
    }
  };

  const handleDelete = (row: UnifiedRow) => {
    modal.confirm({
      title: `删除客户端 "${row.name}"？`,
      content:
        "此操作不可撤销，客户端将无法再使用当前 key 连接；其端口映射与会话也会被一并清理。",
      okType: "danger",
      onOk: async () => {
        try {
          await deleteRegistryEntry(row.name);
          message.success("已删除");
          await reload();
        } catch {
          message.error("删除失败");
        }
      },
    });
  };

  const handleRegenKey = (row: UnifiedRow) => {
    modal.confirm({
      title: `重新生成 "${row.name}" 的 Key？`,
      content: "旧 key 将立即失效，客户端需要使用新 key 重连。",
      okType: "danger",
      onOk: async () => {
        try {
          await regenerateRegistryKey(row.name);
          message.success("Key 已更新");
          await reload();
        } catch {
          message.error("操作失败");
        }
      },
    });
  };

  const handleDisconnect = (row: UnifiedRow) => {
    if (row.clientId == null) return;
    modal.confirm({
      title: "踢下线？",
      content:
        "停止监听并断开当前控制连接，客户端可以使用相同 key 重新连接。端口映射会被保留。",
      onOk: async () => {
        try {
          await disconnectClient(row.clientId!);
          message.success("已断开");
          await reload();
        } catch {
          message.error("操作失败");
        }
      },
    });
  };

  const openAddMapping = (row: UnifiedRow) => {
    if (row.clientId == null) {
      message.warning("客户端从未连接过，无法直接添加映射；请等待首次连接。");
      return;
    }
    setMappingTargetClientId(row.clientId);
    mappingForm.resetFields();
    mappingForm.setFieldsValue({ protocol: "tcp" });
    setMappingModalOpen(true);
  };

  const submitMapping = async () => {
    if (mappingTargetClientId == null) return;
    const v = await mappingForm.validateFields();
    const isHttpProxy = v.protocol === "http_proxy";
    try {
      await addMapping(mappingTargetClientId, {
        server_port: v.server_port,
        protocol: v.protocol,
        // For http_proxy mappings the server resolves the target
        // dynamically to the client's current HTTP proxy port, so the
        // host/port fields are omitted entirely.
        ...(isHttpProxy
          ? {}
          : { target_host: v.target_host, target_port: v.target_port }),
      });
      message.success("映射已添加");
      setMappingModalOpen(false);
      await reload();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } };
      message.error(err.response?.data?.message ?? "添加映射失败");
    }
  };

  const mappingProtocol = Form.useWatch("protocol", mappingForm);
  const mappingIsHttpProxy = mappingProtocol === "http_proxy";

  const columns: ColumnsType<UnifiedRow> = useMemo(
    () => [
      {
        title: "名称",
        dataIndex: "name",
        width: 160,
        render: (name: string) => <Typography.Text strong>{name}</Typography.Text>,
      },
      {
        title: "状态",
        dataIndex: "status",
        width: 110,
        render: (s: UnifiedRow["status"]) =>
          s === "online" ? (
            <Tag color="green">online</Tag>
          ) : (
            <Tag>offline</Tag>
          ),
      },
      {
        title: "远端地址",
        dataIndex: "remoteAddr",
        render: (v?: string | null) => v ?? "-",
      },
      {
        title: "HTTP proxy",
        dataIndex: "httpProxyPort",
        width: 180,
        render: (p?: number | null) => (p ? `127.0.0.1:${p}` : "-"),
      },
      {
        title: "Key",
        dataIndex: "key",
        width: 260,
        render: (key: string) => (
          <Space>
            <Typography.Text code style={{ fontSize: 12 }}>
              {key.length > 20 ? `${key.slice(0, 20)}…` : key}
            </Typography.Text>
            <Tooltip title="复制完整 key">
              <Button
                type="text"
                size="small"
                icon={<CopyOutlined />}
                onClick={() => copyToClipboard(key)}
              />
            </Tooltip>
          </Space>
        ),
      },
      {
        title: "描述",
        dataIndex: "description",
        render: (v?: string | null) => v ?? "-",
      },
      {
        title: "创建时间",
        dataIndex: "createdAt",
        width: 170,
        render: (ts: number) => new Date(ts * 1000).toLocaleString(),
      },
      {
        title: "操作",
        key: "actions",
        width: 280,
        render: (_, row) => (
          <Space>
            <Tooltip title="添加端口映射">
              <Button size="small" onClick={() => openAddMapping(row)}>
                添加映射
              </Button>
            </Tooltip>
            <Tooltip title="编辑描述">
              <Button
                size="small"
                onClick={() => {
                  setEditRow(row);
                  editForm.setFieldsValue({ description: row.description });
                }}
              >
                编辑
              </Button>
            </Tooltip>
            <Tooltip title="重新生成 Key">
              <Button
                size="small"
                icon={<KeyOutlined />}
                onClick={() => handleRegenKey(row)}
              />
            </Tooltip>
            {row.status === "online" && (
              <Tooltip title="踢下线">
                <Button
                  size="small"
                  icon={<DisconnectOutlined />}
                  onClick={() => handleDisconnect(row)}
                />
              </Tooltip>
            )}
            <Tooltip title="删除客户端">
              <Button
                size="small"
                danger
                icon={<DeleteOutlined />}
                onClick={() => handleDelete(row)}
              />
            </Tooltip>
          </Space>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [reload],
  );

  const expandedRowRender = (row: UnifiedRow) => {
    const mappingColumns: ColumnsType<MappingDto> = [
      { title: "服务端端口", dataIndex: "server_port", width: 140 },
      { title: "协议", dataIndex: "protocol", width: 100 },
      { title: "目标", dataIndex: "target" },
      {
        title: "上行",
        dataIndex: "bytes_up",
        width: 110,
        render: (n: number) => formatBytes(n),
      },
      {
        title: "下行",
        dataIndex: "bytes_down",
        width: 110,
        render: (n: number) => formatBytes(n),
      },
      {
        title: "活动会话",
        dataIndex: "active_connections",
        width: 110,
      },
      {
        title: "操作",
        key: "a",
        width: 120,
        render: (_, m) => (
          <Button
            size="small"
            danger
            onClick={async () => {
              if (row.clientId == null) return;
              try {
                await deleteMapping(row.clientId, m.server_port);
                message.success("映射已删除");
                await reload();
              } catch {
                message.error("删除映射失败");
              }
            }}
          >
            删除
          </Button>
        ),
      },
    ];

    return (
      <Table<MappingDto>
        size="small"
        rowKey={(m) => `${m.server_port}-${m.protocol}`}
        columns={mappingColumns}
        dataSource={row.mappings}
        pagination={false}
        locale={{ emptyText: "暂无端口映射" }}
      />
    );
  };

  return (
    <div>
      <Typography.Title level={3} style={{ marginTop: 0, marginBottom: 16 }}>
        客户端管理
      </Typography.Title>

      <Space style={{ marginBottom: 16 }}>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            createForm.resetFields();
            setCreateOpen(true);
          }}
        >
          新建客户端
        </Button>
        <Button
          icon={<ReloadOutlined />}
          onClick={() => reload()}
          loading={loading}
        >
          刷新
        </Button>
      </Space>

      <Table<UnifiedRow>
        rowKey="name"
        loading={loading}
        columns={columns}
        dataSource={rows}
        pagination={false}
        expandable={{ expandedRowRender }}
      />

      <Modal
        title="新建客户端条目"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={handleCreate}
        destroyOnClose
      >
        <Form form={createForm} layout="vertical">
          <Form.Item
            name="name"
            label="客户端名称"
            rules={[
              { required: true, message: "请输入名称" },
              { pattern: /^[a-zA-Z0-9_-]+$/, message: "只允许字母、数字、- 和 _" },
            ]}
          >
            <Input placeholder="my-client" />
          </Form.Item>
          <Form.Item name="description" label="描述（可选）">
            <Input placeholder="描述信息" />
          </Form.Item>
        </Form>
        <Typography.Text type="secondary">
          Key 将在创建后自动生成。
        </Typography.Text>
      </Modal>

      <Modal
        title="编辑客户端条目"
        open={!!editRow}
        onCancel={() => setEditRow(null)}
        onOk={handleEdit}
        destroyOnClose
      >
        <Form form={editForm} layout="vertical">
          <Form.Item name="description" label="描述">
            <Input placeholder="描述信息" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="添加端口映射"
        open={mappingModalOpen}
        onCancel={() => setMappingModalOpen(false)}
        onOk={submitMapping}
        destroyOnClose
      >
        <Form form={mappingForm} layout="vertical">
          <Form.Item
            name="server_port"
            label="服务端端口"
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={65535} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item
            name="protocol"
            label="协议"
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { value: "tcp", label: "tcp" },
                { value: "udp", label: "udp" },
                { value: "both", label: "both" },
                {
                  value: "http_proxy",
                  label: "http_proxy（自动转发到客户端本地 HTTP 代理）",
                },
              ]}
            />
          </Form.Item>
          {mappingIsHttpProxy ? (
            <Typography.Paragraph type="secondary" style={{ marginTop: -8 }}>
              服务端监听 TCP，自动转发到客户端当前随机 HTTP 代理端口；客户端重启后会自动重新映射。
            </Typography.Paragraph>
          ) : (
            <>
              <Form.Item
                name="target_host"
                label="目标 Host"
                rules={[{ required: true }]}
              >
                <Input placeholder="192.168.1.10 或 example.com" />
              </Form.Item>
              <Form.Item
                name="target_port"
                label="目标端口"
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={65535} style={{ width: "100%" }} />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>
    </div>
  );
}
