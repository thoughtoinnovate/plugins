/**
 * Inline completion provider backed by the optional
 * `_tark/inlineCompletion` ACP extension (R8 S22, R11, S27).
 *
 * Stale-suppression contract: a completion is applied only when, at resolve
 * time, (a) the document version still matches the request's
 * `bufferVersion`, (b) the request is still the latest issued for that
 * document, and (c) the backend echoed the same `clientRequestId`. Late,
 * cancelled, or superseded results are discarded so accepted text can never
 * land in the wrong buffer version.
 */
import * as vscode from "vscode";
import { InlineCompletionResult } from "./acpClient";

/** Backend operations the completion provider drives; implemented in `extension.ts`. */
export interface CompletionBackend {
  ensureCompletionSession(): Promise<string>;
  requestCompletion(args: {
    sessionId: string;
    path: string;
    line: number;
    col: number;
    prefix: string;
    suffix: string;
    language?: string;
    triggerKind?: string;
    clientRequestId: string;
    bufferVersion: number;
  }): Promise<InlineCompletionResult>;
  completionEnabled(): boolean;
}

const MAX_CONTEXT_CHARS = 4000;

export class TarkCompletionProvider implements vscode.InlineCompletionItemProvider {
  private requestCounter = 0;
  private readonly latestByDocument = new Map<string, string>();

  public constructor(
    private readonly backend: CompletionBackend,
    private readonly log: (line: string) => void,
  ) {}

  public async provideInlineCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position,
    context: vscode.InlineCompletionContext,
    // Justification: signature is dictated by the vscode API; the token is
    // intentionally unused (stale suppression uses document versions).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _token: any,
  ): Promise<vscode.InlineCompletionList | undefined> {
    if (!this.backend.completionEnabled()) {
      return undefined;
    }
    if (document.isClosed || document.uri.scheme !== "file") {
      return undefined;
    }
    const documentVersion = document.version;
    const documentKey = document.uri.toString();
    const clientRequestId = `vscode-${Date.now()}-${this.requestCounter++}`;
    this.latestByDocument.set(documentKey, clientRequestId);

    const fullText = document.getText();
    const offset = document.offsetAt(position);
    const prefix = fullText.slice(Math.max(0, offset - MAX_CONTEXT_CHARS), offset);
    const suffix = fullText.slice(offset, offset + MAX_CONTEXT_CHARS);
    const triggerKind =
      context.triggerKind === vscode.InlineCompletionTriggerKind.Automatic
        ? "automatic"
        : "manual";

    let sessionId: string;
    try {
      sessionId = await this.backend.ensureCompletionSession();
    } catch (err) {
      this.log(`inline completion: no session (${err instanceof Error ? err.message : String(err)})`);
      return undefined;
    }

    let result: InlineCompletionResult;
    try {
      result = await this.backend.requestCompletion({
        sessionId,
        path: document.uri.fsPath,
        line: position.line,
        col: position.character,
        prefix,
        suffix,
        language: document.languageId,
        triggerKind,
        clientRequestId,
        bufferVersion: documentVersion,
      });
    } catch (err) {
      // Degrade silently to standard editing; chat remains usable (R8 S22).
      this.log(`inline completion request failed: ${err instanceof Error ? err.message : String(err)}`);
      return undefined;
    }

    // Stale suppression: never apply a late or superseded result.
    if (document.isClosed || document.version !== documentVersion) {
      return undefined;
    }
    if (this.latestByDocument.get(documentKey) !== clientRequestId) {
      return undefined;
    }
    if (result.clientRequestId !== undefined && result.clientRequestId !== clientRequestId) {
      this.log(`inline completion: discarding mismatched clientRequestId ${String(result.clientRequestId)}`);
      return undefined;
    }
    if (result.bufferVersion !== undefined && result.bufferVersion !== documentVersion) {
      return undefined;
    }
    const completion = result.completion;
    if (!completion || completion.length === 0) {
      return undefined;
    }
    const item = new vscode.InlineCompletionItem(
      completion,
      new vscode.Range(position, position),
    );
    return new vscode.InlineCompletionList([item]);
  }
}
