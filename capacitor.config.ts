import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.aegismesh.vpn',
  appName: 'AegisMesh VPN',
  webDir: 'dist/renderer',
  server: {
    androidScheme: 'https',
    cleartext: true,
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 1200,
      backgroundColor: '#080B10',
    },
  },
};

export default config;
