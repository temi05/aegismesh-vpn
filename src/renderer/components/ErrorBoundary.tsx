// Перехватчик ошибок рендера (защита от чёрного экрана на мобильных устройствах и ПК)
import React from 'react';

interface State {
  hasError: boolean;
  errorMessage: string;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  public state: State = {
    hasError: false,
    errorMessage: '',
  };

  public static getDerivedStateFromError(error: unknown): State {
    return {
      hasError: true,
      errorMessage: error instanceof Error ? error.message : String(error),
    };
  }

  private handleResetAndReload = () => {
    try {
      globalThis.localStorage?.removeItem('aegismesh_mobile_standalone_v1');
      globalThis.localStorage?.removeItem('aegismesh_mobile_native_v2');
    } catch {
      // Игнорируем ограничения WebView
    }
    window.location.reload();
  };

  public render(): React.ReactNode {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '100vh',
            backgroundColor: '#070a0f',
            color: '#dde2f2',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
            fontFamily: 'system-ui, -apple-system, sans-serif',
          }}
        >
          <div
            style={{
              maxWidth: '420px',
              width: '100%',
              background: '#0d131e',
              border: '1px solid #00f59b',
              borderRadius: '12px',
              padding: '20px',
            }}
          >
            <h2 style={{ color: '#00f59b', fontSize: '18px', marginBottom: '8px' }}>
              Восстановление интерфейса AegisMesh VPN
            </h2>
            <p style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '12px' }}>
              Произошла ошибка состояния интерфейса: {this.state.errorMessage}
            </p>
            <button
              type="button"
              onClick={this.handleResetAndReload}
              style={{
                width: '100%',
                padding: '12px',
                background: '#00f59b',
                color: '#003920',
                border: 'none',
                borderRadius: '8px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              Восстановить и перезапустить
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
