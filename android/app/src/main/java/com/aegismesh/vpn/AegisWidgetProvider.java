package com.aegismesh.vpn;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.widget.RemoteViews;

/**
 * Нативный тактический виджет AegisMesh VPN на рабочий стол Android (4x1):
 * отображает живой статус туннеля и текущий сервер, позволяет включать/выключать VPN
 * и мгновенно переключаться на следующий быстрый резерв (⚡) в 1 нажатие.
 */
public class AegisWidgetProvider extends AppWidgetProvider {
    public static final String ACTION_WIDGET_TOGGLE = "com.aegismesh.vpn.WIDGET_TOGGLE";
    public static final String ACTION_WIDGET_NEXT = "com.aegismesh.vpn.WIDGET_NEXT";

    public static void refreshAllWidgets(Context context) {
        if (context == null) return;
        try {
            Context appCtx = context.getApplicationContext();
            AppWidgetManager manager = AppWidgetManager.getInstance(appCtx);
            int[] ids = manager.getAppWidgetIds(new ComponentName(appCtx, AegisWidgetProvider.class));
            if (ids != null && ids.length > 0) {
                for (int appWidgetId : ids) {
                    updateSingleWidget(appCtx, manager, appWidgetId);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        if (appWidgetIds == null) return;
        for (int appWidgetId : appWidgetIds) {
            updateSingleWidget(context, appWidgetManager, appWidgetId);
        }
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);
        if (context == null || intent == null) return;
        String action = intent.getAction();

        if (ACTION_WIDGET_TOGGLE.equals(action)) {
            if (AegisVpnService.isVpnRunning() || AegisVpnService.isVpnStarting()) {
                Intent stopIntent = new Intent(context, AegisVpnService.class);
                stopIntent.setAction(AegisVpnService.ACTION_STOP);
                context.startService(stopIntent);
            } else if (VpnService.prepare(context) == null && AegisVpnService.hasSavedSession(context)) {
                Intent startIntent = new Intent(context, AegisVpnService.class);
                startIntent.setAction(AegisVpnService.ACTION_START_FROM_SAVED);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(startIntent);
                } else {
                    context.startService(startIntent);
                }
            } else {
                Intent openIntent = new Intent(context, MainActivity.class);
                openIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                context.startActivity(openIntent);
            }
            refreshAllWidgets(context);
        } else if (ACTION_WIDGET_NEXT.equals(action)) {
            if (AegisVpnService.isVpnRunning()) {
                Intent nextIntent = new Intent(context, AegisVpnService.class);
                nextIntent.setAction(AegisVpnService.ACTION_NEXT_NODE);
                context.startService(nextIntent);
            } else {
                Intent openIntent = new Intent(context, MainActivity.class);
                openIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                context.startActivity(openIntent);
            }
        }
    }

    private static void updateSingleWidget(Context context, AppWidgetManager manager, int appWidgetId) {
        RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.aegis_widget);
        boolean running = AegisVpnService.isVpnRunning();
        String activeName = AegisVpnService.getActiveNodeName();

        if (running) {
            views.setTextViewText(R.id.tv_widget_status, "🛡️ VPN РАБОТАЕТ • АВТОЗАМЕНА 24/7");
            views.setTextColor(R.id.tv_widget_status, Color.parseColor("#00E5B0"));
            views.setTextViewText(
                    R.id.tv_widget_server,
                    (activeName != null && !activeName.isEmpty()) ? activeName : "Защищённый каскад активен"
            );
            views.setTextViewText(R.id.btn_widget_toggle, "ВЫКЛ");
        } else {
            views.setTextViewText(R.id.tv_widget_status, "⚪ AEGISMESH VPN • ВЫКЛЮЧЕН");
            views.setTextColor(R.id.tv_widget_status, Color.parseColor("#94A3B8"));
            views.setTextViewText(
                    R.id.tv_widget_server,
                    AegisVpnService.hasSavedSession(context)
                            ? "Нажмите ВКЛ для мгновенного старта"
                            : "Откройте приложение и добавьте VPN"
            );
            views.setTextViewText(R.id.btn_widget_toggle, "ВКЛ");
        }

        int piFlags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                ? PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
                : PendingIntent.FLAG_UPDATE_CURRENT;

        Intent openAppIntent = new Intent(context, MainActivity.class);
        openAppIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent openPending = PendingIntent.getActivity(context, 4200, openAppIntent, piFlags);
        views.setOnClickPendingIntent(R.id.widget_root, openPending);

        Intent toggleIntent = new Intent(context, AegisWidgetProvider.class);
        toggleIntent.setAction(ACTION_WIDGET_TOGGLE);
        PendingIntent togglePending = PendingIntent.getBroadcast(context, 4201, toggleIntent, piFlags);
        views.setOnClickPendingIntent(R.id.btn_widget_toggle, togglePending);

        Intent nextIntent = new Intent(context, AegisWidgetProvider.class);
        nextIntent.setAction(ACTION_WIDGET_NEXT);
        PendingIntent nextPending = PendingIntent.getBroadcast(context, 4202, nextIntent, piFlags);
        views.setOnClickPendingIntent(R.id.btn_widget_next, nextPending);

        manager.updateAppWidget(appWidgetId, views);
    }
}
