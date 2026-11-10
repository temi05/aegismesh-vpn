package com.aegismesh.vpn;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import androidx.annotation.RequiresApi;

/**
 * Плитка быстрого включения/выключения AegisMesh VPN в верхней шторке Android (Quick Settings Tile).
 * Позволяет запускать и останавливать Мульти-VPN каскад в 1 нажатие без открытия приложения.
 */
@RequiresApi(api = Build.VERSION_CODES.N)
public class AegisTileService extends TileService {

    public static void requestTileSync(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && context != null) {
            try {
                TileService.requestListeningState(
                        context.getApplicationContext(),
                        new ComponentName(context.getApplicationContext(), AegisTileService.class)
                );
            } catch (Throwable ignored) {
            }
        }
    }

    @Override
    public void onStartListening() {
        super.onStartListening();
        syncTileUi();
    }

    @Override
    public void onClick() {
        super.onClick();
        if (AegisVpnService.isVpnRunning() || AegisVpnService.isVpnStarting()) {
            Intent stopIntent = new Intent(this, AegisVpnService.class);
            stopIntent.setAction(AegisVpnService.ACTION_STOP);
            startService(stopIntent);
            Tile tile = getQsTile();
            if (tile != null) {
                tile.setState(Tile.STATE_INACTIVE);
                tile.setLabel("AegisMesh VPN");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.setSubtitle("Выключен");
                }
                tile.updateTile();
            }
            return;
        }

        // Если разрешение VPN уже выдано и есть сохранённый профиль каскада — запускаем мгновенно в фоне!
        if (VpnService.prepare(this) == null && AegisVpnService.hasSavedSession(this)) {
            Intent startIntent = new Intent(this, AegisVpnService.class);
            startIntent.setAction(AegisVpnService.ACTION_START_FROM_SAVED);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent);
            } else {
                startService(startIntent);
            }
            Tile tile = getQsTile();
            if (tile != null) {
                tile.setState(Tile.STATE_ACTIVE);
                tile.setLabel("AegisMesh VPN");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.setSubtitle("Подключение...");
                }
                tile.updateTile();
            }
            return;
        }

        // Иначе открываем приложение для выдачи первого системного разрешения VPN или добавления ключей
        openMainAppFromTile();
    }

    private void openMainAppFromTile() {
        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        if (Build.VERSION.SDK_INT >= 34) {
            PendingIntent pi = PendingIntent.getActivity(
                    this,
                    4101,
                    openIntent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );
            startActivityAndCollapse(pi);
        } else {
            startActivityAndCollapse(openIntent);
        }
    }

    private void syncTileUi() {
        Tile tile = getQsTile();
        if (tile == null) return;

        boolean running = AegisVpnService.isVpnRunning();
        String nodeName = AegisVpnService.getActiveNodeName();
        tile.setIcon(Icon.createWithResource(this, R.drawable.ic_aegis_shield));
        tile.setLabel("AegisMesh VPN");

        if (running) {
            tile.setState(Tile.STATE_ACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.setSubtitle((nodeName != null && !nodeName.isEmpty()) ? nodeName : "Щит активен");
            }
        } else {
            tile.setState(Tile.STATE_INACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.setSubtitle("Выключен");
            }
        }
        tile.updateTile();
    }
}
