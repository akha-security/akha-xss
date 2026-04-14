"""
Payload manager
"""

import os
from typing import List, Optional
from akha.payloads.database import PayloadDatabase
from akha.payloads.generator import PayloadGenerator


class PayloadManager:
    """Manages payload selection and loading"""
    
    def __init__(self, config):
        self.config = config
        self.database = PayloadDatabase()
        self.generator = PayloadGenerator()
        self.custom_payloads = self._load_custom_payloads()
    
    def _load_custom_payloads(self) -> List[str]:
        """Load custom payloads from file"""
        if not self.config.custom_payloads_file:
            return []
        
        if not os.path.exists(self.config.custom_payloads_file):
            return []
        
        try:
            with open(self.config.custom_payloads_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        except Exception as e:
            if self.config.verbose:
                print(f"Error loading custom payloads: {e}")
            return []
    
    def get_payloads(self, context: Optional[str] = None, waf_name: Optional[str] = None) -> List[str]:
        """
        Get payloads based on strategy
        
        Args:
            context: Target context (HTML, JavaScript, etc.)
            waf_name: Detected WAF name
        
        Returns:
            List of payloads
        """
        if self.config.payload_strategy == 'auto':
            return self._get_auto_payloads(context, waf_name)
        
        elif self.config.payload_strategy == 'builtin':
            return self._get_builtin_payloads(context, waf_name)
        
        elif self.config.payload_strategy == 'custom':
            return self._get_custom_payloads()
        
        elif self.config.payload_strategy == 'hybrid':
            return self._get_hybrid_payloads(context, waf_name)
        
        else:
            return self._get_builtin_payloads(context, waf_name)
    
    def _get_auto_payloads(self, context: Optional[str], waf_name: Optional[str]) -> List[str]:
        """Smart payload selection"""
        payloads = []
        
        if context:
            payloads.extend(self.generator.generate_for_context(context, waf_name))
        else:
            for ctx in ['HTML', 'Attribute', 'JavaScript', 'URL']:
                payloads.extend(self.generator.generate_for_context(ctx, waf_name)[:10])
        
        if waf_name:
            waf_key = waf_name.lower().replace(' ', '_')
            if 'cloudflare' in waf_key:
                payloads.extend(self.database.get_by_category('waf_bypass_cloudflare')[:10])
            elif 'akamai' in waf_key:
                payloads.extend(self.database.get_by_category('waf_bypass_akamai')[:10])
            else:
                payloads.extend(self.database.get_by_category('waf_bypass_generic')[:10])
        
        payloads.extend(self.database.get_by_category('polyglot')[:5])

        if getattr(self.config, 'aggressive_mode', False):
            payloads.extend(self.database.get_by_category('aggressive'))
        
        return payloads[:50]
    
    def _get_builtin_payloads(self, context: Optional[str], waf_name: Optional[str]) -> List[str]:
        """Get built-in database payloads"""
        payloads = []
        
        if context:
            context_key = f"context_{context.lower()}"
            payloads.extend(self.database.get_by_category(context_key))
        
        payloads.extend(self.database.get_by_category('basic'))
        
        payloads.extend(self.database.get_by_category('event_handlers')[:20])
        
        payloads.extend(self.database.get_by_category('svg_based'))
        
        payloads.extend(self.database.get_by_category('polyglot'))

        if getattr(self.config, 'aggressive_mode', False):
            payloads.extend(self.database.get_by_category('aggressive'))
        
        if waf_name:
            waf_key = waf_name.lower().replace(' ', '_')
            if 'cloudflare' in waf_key:
                payloads.extend(self.database.get_by_category('waf_bypass_cloudflare'))
            elif 'akamai' in waf_key:
                payloads.extend(self.database.get_by_category('waf_bypass_akamai'))
            else:
                payloads.extend(self.database.get_by_category('waf_bypass_generic'))
        
        return payloads[:100]
    
    def _get_custom_payloads(self) -> List[str]:
        """Get custom payloads"""
        return self.custom_payloads or self.database.get_by_category('basic')
    
    def _get_hybrid_payloads(self, context: Optional[str], waf_name: Optional[str]) -> List[str]:
        """Get hybrid (builtin + custom) payloads"""
        payloads = []
        
        payloads.extend(self.custom_payloads)
        
        payloads.extend(self._get_auto_payloads(context, waf_name))
        
        payloads.extend(self.database.get_by_category('basic')[:20])
        payloads.extend(self.database.get_by_category('polyglot')[:10])
        if getattr(self.config, 'aggressive_mode', False):
            payloads.extend(self.database.get_by_category('aggressive'))
        
        return payloads[:150]
