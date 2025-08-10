import yagmail

def send_threat_report(subject, body, attachments=None):
    yag = yagmail.SMTP(
        user="aihunter_sentinel@pm.me",
        password="0oIf_hNSGWrQAmtVOGLg",  # <- usa el que ves en Bridge, no cambies esto por tu login de Proton normal
        host="127.0.0.1",
        port=1025,
        smtp_starttls=True,
        smtp_ssl=False
    )

    yag.send(
        to="aihunter_sentinel@pm.me",
        subject=subject,
        contents=body,
        attachments=attachments
    )
