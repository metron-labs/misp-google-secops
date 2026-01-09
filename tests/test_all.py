import unittest
import sys
import os

# Add parent directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock, patch
from src.secops.manager import SecOpsManager
from src.misp.client import MispClient

class TestIntegration(unittest.TestCase):
    # No helper client needed for static methods test, or we can mock credentials load if we instantiate
    # But for conversion test, we can call static method directly if we kept it static.
    # I kept convert_to_entity as static.
    pass

    def test_entity_conversion_ip(self):
        misp_attr = {
            'type': 'ip-src',
            'value': '1.2.3.4',
            'timestamp': '1600000000',
            'comment': 'Malicious IP',
            'Event': {
                'info': 'Test Event',
                'uuid': '1234',
                'threat_level_id': '2',
                'Orgc': {'name': 'TestOrg'}
            }
        }   
        entity_ctx = SecOpsManager.convert_to_entity(misp_attr)
        self.assertIsNotNone(entity_ctx)
        self.assertEqual(entity_ctx['entity']['ip'], '1.2.3.4')
        self.assertEqual(entity_ctx['metadata']['product_name'], 'MISP')
        self.assertEqual(entity_ctx['metadata']['entity_type'], 'IP_ADDRESS')
        self.assertEqual(entity_ctx['metadata']['threat'][0]['severity'], 'HIGH')

    def test_entity_conversion_hash(self):
        misp_attr = {
            'type': 'sha256',
            'value': 'deadbeef',
            'timestamp': '1600000000',
            'Event': {'info': 'Hash Event'}
        }
        entity_ctx = SecOpsManager.convert_to_entity(misp_attr)
        self.assertEqual(entity_ctx['entity']['file']['sha256'], 'deadbeef')
        self.assertEqual(entity_ctx['metadata']['entity_type'], 'FILE')

    @patch('requests.post')
    def test_misp_fetch(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response': {
                'Attribute': [{'id': 1}, {'id': 2}]
            }
        }
        mock_post.return_value = mock_response

        # Mock config
        with patch('src.config.Config.MISP_URL', 'http://misp'), \
             patch('src.config.Config.MISP_API_KEY', 'key'):
            client = MispClient()
            attrs = client.fetch_attributes(page=1)
            self.assertEqual(len(attrs), 2)

if __name__ == '__main__':
    unittest.main()
