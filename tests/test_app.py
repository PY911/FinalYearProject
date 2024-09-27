import unittest
from scripts.app import app  # Corrected import

class FlaskTestCase(unittest.TestCase):

    # Test if login POST method works with correct credentials
    def test_valid_login(self):
        tester = app.test_client(self)
        response = tester.post('/login', data=dict(email="testuser@example.com", password="Password123"), follow_redirects=True)
        self.assertIn(b'Successfully logged in.', response.data)

if __name__ == '__main__':
    unittest.main()
