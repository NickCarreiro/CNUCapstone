import base64
import os

print(base64.urlsafe_b64encode(os.urandom(32)).decode())
