import imaplib
import email
from email.header import decode_header

# Connexion au serveur IMAP
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = ""
PASSWORD = ""  # Utiliser OAuth2 si possible

def fetch_emails():
    # Connexion au serveur
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, PASSWORD)
    mail.select("inbox")

    # Récupérer les emails non lus
    status, messages = mail.search(None, 'UNSEEN')

    emails = []
    for num in messages[0].split():
        _, msg_data = mail.fetch(num, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                # Décoder l'expéditeur et le sujet
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes) and encoding:
                    subject = subject.decode(encoding)
                
                sender = msg.get("From")

                # Extraire le contenu
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")

                emails.append({"from": sender, "subject": subject, "body": body})

    mail.logout()
    return emails

# Test de récupération
emails = fetch_emails()
for email_data in emails:
    print(f"De : {email_data['from']}\nSujet : {email_data['subject']}\nMessage : {email_data['body'][:200]}...\n")
