import MarkdownIt from 'markdown-it/lib/index.js';
import linkifyIt from 'linkify-it';
import punycode from 'punycode';

// Configure markdown-it with only non-default options
const md = new MarkdownIt({
  html: false, // Disable HTML tags (default: true)
  linkify: false // Explicitly disable autolinking (default: false)
});

// Attach linkify-it instance
md.linkify = new linkifyIt();

// Attach punycode
md.punycode = punycode;

// Define validation and normalization functions
md.validateLink = function(url) {
  const re = /^(vbscript|javascript|file|data):/;
  const imgRe = /^data:image\/(gif|png|jpeg|webp);/;
  const str = url.trim().toLowerCase();
  return !re.test(str) || imgRe.test(str);
};

md.normalizeLink = function(url) {
  const parsed = new URL(url, 'http://example.com');
  if (parsed.hostname && (!parsed.protocol || ['http:', 'https:', 'mailto:'].includes(parsed.protocol))) {
    try {
      parsed.hostname = punycode.toASCII(parsed.hostname);
    } catch (e) {}
  }
  return parsed.toString();
};

md.normalizeLinkText = function(url) {
  const parsed = new URL(url, 'http://example.com');
  if (parsed.hostname && (!parsed.protocol || ['http:', 'https:', 'mailto:'].includes(parsed.protocol))) {
    try {
      parsed.hostname = punycode.toUnicode(parsed.hostname);
    } catch (e) {}
  }
  return decodeURI(parsed.toString());
};

// Expose as global variable
if (typeof window !== 'undefined') {
  window.markdownit = MarkdownIt;
}

// Export for ES module usage
export default MarkdownIt;
