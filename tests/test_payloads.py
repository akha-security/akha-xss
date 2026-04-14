"""
Test payload system
"""

import unittest
from akha.payloads.database import PayloadDatabase
from akha.payloads.generator import PayloadGenerator
from akha.payloads.manager import PayloadManager
from akha.core.config import Config


class TestPayloads(unittest.TestCase):
    """Test payload system"""
    
    def setUp(self):
        """Setup test"""
        self.database = PayloadDatabase()
        self.generator = PayloadGenerator()
        self.config = Config.default()
        self.manager = PayloadManager(self.config)
    
    def test_database_load(self):
        """Test payload database loading"""
        payloads = self.database.get_all()
        self.assertGreater(len(payloads), 0)
    
    def test_basic_payloads(self):
        """Test basic payloads"""
        basic = self.database.get_by_category('basic')
        self.assertGreater(len(basic), 0)
    
    def test_generator_html(self):
        """Test HTML payload generation"""
        payloads = self.generator.generate_for_context('HTML')
        self.assertGreater(len(payloads), 0)
    
    def test_manager_get_payloads(self):
        """Test payload manager"""
        payloads = self.manager.get_payloads()
        self.assertGreater(len(payloads), 0)


if __name__ == '__main__':
    unittest.main()
