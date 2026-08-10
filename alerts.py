from plyer import notification


def send_alert(title, message):
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="Port Monitor",
            timeout=5
        )
    except Exception as error:
        print(f"[!] Notification failed: {error}")