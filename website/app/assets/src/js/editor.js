import { EditorView } from 'codemirror';
import { basicSetup } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { markdown } from '@codemirror/lang-markdown';

// Expose globals to match original behavior
if (typeof window !== 'undefined') {
  window.EditorView = EditorView;
  window.EditorState = EditorState;
  window.basicSetup = basicSetup;
  window.markdown = markdown;
}

// Export for module usage
export { EditorView,  EditorState, basicSetup, markdown };
