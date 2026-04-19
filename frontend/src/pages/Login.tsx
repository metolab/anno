import { Button, Card, Form, Input, Typography, message, Spin } from "antd";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../api/auth";
import { useAuth, type AuthMode } from "../contexts/AuthContext";

const { Title } = Typography;

function oidcLoginUrl(): string {
  const base = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");
  return base ? `${base}/api/auth/oidc/login` : "/api/auth/oidc/login";
}

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const { signIn, authMode } = useAuth();
  const navigate = useNavigate();
  const [messageApi, contextHolder] = message.useMessage();

  // OIDC callback: fragment #token= or #error=
  useEffect(() => {
    const raw = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : "";
    const params = new URLSearchParams(raw);
    const tok = params.get("token");
    const err = params.get("error");
    if (tok) {
      signIn(tok);
      window.history.replaceState(null, "", "/login");
      navigate("/", { replace: true });
      return;
    }
    if (err) {
      const labels: Record<string, string> = {
        oidc_idp_error: "身份提供商返回错误",
        oidc_not_configured: "服务器未启用 OIDC",
        oidc_missing_param: "回调参数不完整",
        oidc_callback_failed: "OIDC 登录失败",
      };
      messageApi.error(labels[err] ?? `登录失败 (${err})`);
      window.history.replaceState(null, "", "/login");
    }
  }, [signIn, navigate, messageApi]);

  useEffect(() => {
    if (authMode === "none") {
      navigate("/", { replace: true });
    }
  }, [authMode, navigate]);

  const onFinish = async (values: { password: string }) => {
    setLoading(true);
    try {
      const res = await login(values.password);
      signIn(res.token);
      navigate("/");
    } catch {
      messageApi.error("密码错误或服务器异常");
    } finally {
      setLoading(false);
    }
  };

  if (authMode === null) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#f0f2f5",
        }}
      >
        <Spin size="large" />
      </div>
    );
  }

  const mode: AuthMode = authMode;

  if (mode === "none") {
    return null;
  }

  if (mode === "oidc") {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#f0f2f5",
        }}
      >
        {contextHolder}
        <Card style={{ width: 360, boxShadow: "0 4px 24px rgba(0,0,0,0.08)" }}>
          <div style={{ textAlign: "center", marginBottom: 32 }}>
            <Title level={3} style={{ margin: 0 }}>
              anno
            </Title>
            <Typography.Text type="secondary">使用 SSO 登录管理后台</Typography.Text>
          </div>
          <Button
            type="primary"
            size="large"
            block
            onClick={() => {
              window.location.assign(oidcLoginUrl());
            }}
          >
            使用 SSO 登录
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#f0f2f5",
      }}
    >
      {contextHolder}
      <Card style={{ width: 360, boxShadow: "0 4px 24px rgba(0,0,0,0.08)" }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <Title level={3} style={{ margin: 0 }}>
            anno
          </Title>
          <Typography.Text type="secondary">请输入管理密码</Typography.Text>
        </div>
        <Form layout="vertical" onFinish={onFinish}>
          <Form.Item
            name="password"
            rules={[{ required: true, message: "请输入密码" }]}
          >
            <Input.Password placeholder="密码" size="large" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0 }}>
            <Button
              type="primary"
              htmlType="submit"
              size="large"
              block
              loading={loading}
            >
              登录
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
}
