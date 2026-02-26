import sqlite3
import json
import argparse
import base64
import logging
import os  # <-- Add this import
from email.message import EmailMessage

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import google.auth.transport.requests
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError

# --- SIMPLE ERROR LOGGING CONFIGURATION ---
logging.basicConfig(
    filename='gmail_errors.log', 
    level=logging.ERROR, 
    format='%(asctime)s - ERROR - %(message)s'
)

# --- Database Setup (Azure Aware) ---
if 'WEBSITE_SITE_NAME' in os.environ:
    DB_FILE = '/home/oauth_tokens.db'
else:
    DB_FILE = 'oauth_tokens.db'

class GmailManager:
    def __init__(self, target_email):
        self.email = target_email
        self.creds = self._get_valid_credentials()
        
        if self.creds:
            self.service = build('gmail', 'v1', credentials=self.creds)
        else:
            self.service = None

    def _remove_revoked_token(self):
        print(f"[-] Removing revoked or invalid tokens for {self.email} from the database...")
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_tokens WHERE email=?", (self.email,))
        conn.commit()
        conn.close()

    def _get_valid_credentials(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_tokens WHERE email=?", (self.email,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            err_msg = f"No tokens found in database for user '{self.email}'."
            print(f"Error: {err_msg}")
            logging.error(err_msg)
            return None

        creds = Credentials(
            token=row[1], refresh_token=row[2], token_uri=row[3],
            client_id=row[4], client_secret=row[5], scopes=json.loads(row[6])
        )

        if creds.expired or not creds.valid:
            try:
                creds.refresh(google.auth.transport.requests.Request())
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute('UPDATE user_tokens SET access_token=? WHERE email=?', (creds.token, self.email))
                conn.commit()
                conn.close()
            except RefreshError as e:
                print(f"[!] Access Denied: The refresh token for {self.email} is invalid or was revoked by an Admin.")
                print(f"    Google Error: {e}")
                logging.error(f"RefreshError for {self.email}: {e}")
                self._remove_revoked_token()
                return None
            except Exception as e:
                print(f"An unexpected error occurred during token refresh: {e}")
                logging.error(f"Unexpected token refresh error for {self.email}", exc_info=True)
                return None
        
        return creds

    # --- Existing CLI Actions ---

    def list_inbox(self, max_results=10):
        if not self.service: return
        print(f"\n--- Fetching top {max_results} emails for {self.email} ---")
        
        try:
            results = self.service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_results).execute()
            messages = results.get('messages', [])

            if not messages:
                print("Inbox is empty or no messages found.")
                return

            print(f"{'MESSAGE ID':<20} | {'SENDER':<35} | {'SUBJECT'}")
            print("-" * 80)

            for msg in messages:
                msg_data = self.service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata', metadataHeaders=['Subject', 'From']
                ).execute()
                
                headers = msg_data.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)')
                sender_trunc = sender[:32] + "..." if len(sender) > 35 else sender
                
                print(f"{msg['id']:<20} | {sender_trunc:<35} | {subject}")
                
        except HttpError as error:
            self._handle_http_error(error, "listing emails")
        except Exception as e:
            print(f"Unexpected error listing emails: {e}")
            logging.error(f"Unexpected error listing emails for {self.email}", exc_info=True)

    def read_email(self, message_id):
        if not self.service: return
        print(f"\n--- Reading Email ID: {message_id} ---")
        
        try:
            msg = self.service.users().messages().get(userId='me', id=message_id, format='full').execute()
            payload = msg.get('payload', {})
            headers = payload.get('headers', [])

            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), '(Unknown Sender)')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), '(Unknown Date)')

            body_text = self._extract_text_body(payload) or f"(Snippet: {msg.get('snippet')})"

            print(f"From:    {sender}\nDate:    {date}\nSubject: {subject}")
            print("-" * 80 + f"\n{body_text}\n" + "-" * 80)

        except HttpError as error:
            self._handle_http_error(error, "reading email")
        except Exception as e:
            print(f"Unexpected error reading email: {e}")
            logging.error(f"Unexpected error reading email {message_id} for {self.email}", exc_info=True)

    def send_email(self, to, subject, body):
        if not self.service: return
        print(f"\n--- Sending Email as {self.email} ---")
        
        message = EmailMessage()
        message.set_content(body)
        message['To'] = to
        message['From'] = self.email
        message['Subject'] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': encoded_message}

        try:
            send_message = self.service.users().messages().send(userId='me', body=create_message).execute()
            print(f"Success! Email sent to {to}. Message ID: {send_message['id']}")
        except HttpError as error:
            self._handle_http_error(error, "sending email")
        except Exception as e:
            print(f"Unexpected error sending email: {e}")
            logging.error(f"Unexpected error sending email for {self.email}", exc_info=True)

    def delete_email(self, message_id):
        if not self.service: return
        print(f"\n--- Trashing Email ID: {message_id} ---")
        
        try:
            self.service.users().messages().trash(userId='me', id=message_id).execute()
            print(f"Success! Message {message_id} moved to Trash.")
        except HttpError as error:
            self._handle_http_error(error, "deleting email")
        except Exception as e:
            print(f"Unexpected error deleting email: {e}")
            logging.error(f"Unexpected error deleting email {message_id} for {self.email}", exc_info=True)

    def add_delegate(self, delegate_email):
        if not self.service: return
        print(f"\n--- Adding Delegate {delegate_email} to {self.email} ---")
        
        body = {'delegateEmail': delegate_email}
        
        try:
            result = self.service.users().settings().delegates().create(userId='me', body=body).execute()
            status = result.get('verificationStatus', 'UNKNOWN')
            
            print(f"Success! Delegate creation requested for {delegate_email}.")
            print(f"Verification Status: {status}")
            
            if status == 'PENDING':
                print("Note: The delegate will need to accept the request via a confirmation email sent to their inbox.")
        except HttpError as error:
            self._handle_http_error(error, "adding delegate")
        except Exception as e:
            print(f"Unexpected error adding delegate: {e}")
            logging.error(f"Unexpected error adding delegate to {self.email}", exc_info=True)

    # --- NEW: Filter Actions ---

    def list_filters(self):
        if not self.service: return
        print(f"\n--- Fetching Filters for {self.email} ---")
        
        try:
            results = self.service.users().settings().filters().list(userId='me').execute()
            filters = results.get('filter', [])

            if not filters:
                print("No filters found for this account.")
                return

            print(f"{'FILTER ID':<20} | {'CRITERIA':<35} | {'ACTIONS'}")
            print("-" * 80)

            for f in filters:
                criteria = str(f.get('criteria', {}))
                actions = str(f.get('action', {}))
                
                # Truncate for display
                crit_trunc = criteria[:32] + "..." if len(criteria) > 35 else criteria
                act_trunc = actions[:22] + "..." if len(actions) > 25 else actions
                
                print(f"{f['id']:<20} | {crit_trunc:<35} | {act_trunc}")
                
        except HttpError as error:
            self._handle_http_error(error, "listing filters")
        except Exception as e:
            print(f"Unexpected error listing filters: {e}")
            logging.error(f"Unexpected error listing filters for {self.email}", exc_info=True)

    def create_filter(self, criteria_query, add_labels=None, remove_labels=None):
        if not self.service: return
        print(f"\n--- Creating Filter for {self.email} ---")
        
        if not add_labels and not remove_labels:
            print("[!] Error: You must specify at least one action (--add-label or --remove-label).")
            return

        filter_body = {
            'criteria': {
                'query': criteria_query
            },
            'action': {}
        }
        
        if add_labels:
            filter_body['action']['addLabelIds'] = [label.strip() for label in add_labels.split(',')]
        if remove_labels:
            filter_body['action']['removeLabelIds'] = [label.strip() for label in remove_labels.split(',')]

        try:
            result = self.service.users().settings().filters().create(userId='me', body=filter_body).execute()
            print(f"Success! Filter created with ID: {result['id']}")
        except HttpError as error:
            self._handle_http_error(error, "creating filter")
        except Exception as e:
            print(f"Unexpected error creating filter: {e}")
            logging.error(f"Unexpected error creating filter for {self.email}", exc_info=True)

    def delete_filter(self, filter_id):
        if not self.service: return
        print(f"\n--- Deleting Filter ID: {filter_id} ---")
        
        try:
            self.service.users().settings().filters().delete(userId='me', id=filter_id).execute()
            print(f"Success! Filter {filter_id} deleted.")
        except HttpError as error:
            self._handle_http_error(error, "deleting filter")
        except Exception as e:
            print(f"Unexpected error deleting filter: {e}")
            logging.error(f"Unexpected error deleting filter {filter_id} for {self.email}", exc_info=True)

    # --- Helper Methods ---

    def _handle_http_error(self, error, action_name):
        if error.resp.status in [401, 403]:
            err_msg = f"Authorization Error while {action_name} (HTTP {error.resp.status}). Token may be revoked or missing required scopes."
            print(f"[!] {err_msg}")
            logging.error(f"{err_msg} - {error}")
            if error.resp.status == 401: 
                self._remove_revoked_token()
        elif error.resp.status == 404:
            err_msg = f"Not Found: The requested resource while {action_name} does not exist."
            print(f"[-] {err_msg}")
            logging.error(f"{err_msg} - {error}")
        elif error.resp.status == 400:
            print(f"[!] Bad Request: Ensure inputs (like label IDs or delegate email) are valid.")
            logging.error(f"Bad Request while {action_name} - {error}")
        else:
            print(f"[!] API Error while {action_name}: {error}")
            logging.error(f"API Error while {action_name}", exc_info=True)

    def _extract_text_body(self, payload):
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    return self._decode_base64url(part['body'].get('data', ''))
                elif 'parts' in part:
                    result = self._extract_text_body(part)
                    if result: return result
        elif 'body' in payload and payload.get('mimeType') == 'text/plain':
             return self._decode_base64url(payload['body'].get('data', ''))
        return None

    def _decode_base64url(self, data):
        if not data: return ""
        data += "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data.encode('utf-8')).decode('utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Manage a user's Gmail using stored OAuth tokens.")
    parser.add_argument('--email', required=True, help="Target user email.")
    subparsers = parser.add_subparsers(dest="action", help="Action to perform", required=True)

    # Email Management
    list_parser = subparsers.add_parser('list', help="List recent emails in the inbox")
    list_parser.add_argument('--max', type=int, default=10, help="Max emails to retrieve")

    read_parser = subparsers.add_parser('read', help="Read a specific email")
    read_parser.add_argument('message_id', help="ID of the message to read")

    send_parser = subparsers.add_parser('send', help="Send an email")
    send_parser.add_argument('--to', required=True, help="Recipient email address")
    send_parser.add_argument('--subject', required=True, help="Email subject")
    send_parser.add_argument('--body', required=True, help="Email body text")

    delete_parser = subparsers.add_parser('delete', help="Move an email to the trash")
    delete_parser.add_argument('message_id', help="ID of the message to delete")

    # Delegate Management
    delegate_parser = subparsers.add_parser('add-delegate', help="Add a delegate")
    delegate_parser.add_argument('delegate_email', help="Email of the user to be granted delegate access")

    # Filter Management
    filter_list_parser = subparsers.add_parser('list-filters', help="List existing filters")
    
    filter_create_parser = subparsers.add_parser('create-filter', help="Create a new filter")
    filter_create_parser.add_argument('--query', required=True, help="Criteria query (e.g. 'from:spam@example.com')")
    filter_create_parser.add_argument('--add-labels', help="Comma-separated List of Label IDs to add (e.g. TRASH, STARRED)")
    filter_create_parser.add_argument('--remove-labels', help="Comma-separated List of Label IDs to remove (e.g. INBOX to archive)")
    
    filter_delete_parser = subparsers.add_parser('delete-filter', help="Delete an existing filter")
    filter_delete_parser.add_argument('filter_id', help="ID of the filter to delete")

    args = parser.parse_args()
    manager = GmailManager(args.email)

    if manager.service:
        if args.action == 'list':
            manager.list_inbox(max_results=args.max)
        elif args.action == 'read':
            manager.read_email(message_id=args.message_id)
        elif args.action == 'send':
            manager.send_email(to=args.to, subject=args.subject, body=args.body)
        elif args.action == 'delete':
            manager.delete_email(message_id=args.message_id)
        elif args.action == 'add-delegate':
            manager.add_delegate(delegate_email=args.delegate_email)
        elif args.action == 'list-filters':
            manager.list_filters()
        elif args.action == 'create-filter':
            manager.create_filter(criteria_query=args.query, add_labels=args.add_labels, remove_labels=args.remove_labels)
        elif args.action == 'delete-filter':
            manager.delete_filter(filter_id=args.filter_id)
