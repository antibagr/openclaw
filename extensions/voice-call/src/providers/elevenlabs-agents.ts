import type { ElevenLabsAgentsConfig } from "../config.js";
import type {
  GetCallStatusInput,
  GetCallStatusResult,
  HangupCallInput,
  InitiateCallInput,
  InitiateCallResult,
  PlayTtsInput,
  ProviderName,
  ProviderWebhookParseResult,
  StartListeningInput,
  StopListeningInput,
  WebhookContext,
  WebhookParseOptions,
  WebhookVerificationResult,
  NormalizedEvent,
} from "../types.js";
import type { VoiceCallProvider } from "./base.js";

type ConversationStatus = {
  status: string;
  transcript?: Array<{ role: string; message: string }>;
};

async function fetchConversationStatus(
  apiKey: string,
  conversationId: string,
): Promise<ConversationStatus> {
  const res = await fetch(
    `https://api.elevenlabs.io/v1/convai/conversations/${encodeURIComponent(conversationId)}`,
    {
      method: "GET",
      headers: {
        "xi-api-key": apiKey,
        Accept: "application/json",
      },
    },
  );
  if (!res.ok) {
    throw new Error(`ElevenLabs conversation status ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as ConversationStatus;
}

export class ElevenLabsAgentsProvider implements VoiceCallProvider {
  readonly name: ProviderName = "elevenlabs-agents" as ProviderName;

  private readonly config: ElevenLabsAgentsConfig;
  private readonly pollTimers = new Map<string, ReturnType<typeof setInterval>>();
  private readonly seenTranscriptCounts = new Map<string, number>();
  private eventCallback: ((event: NormalizedEvent) => void) | null = null;

  constructor(config: ElevenLabsAgentsConfig) {
    if (!config.apiKey) throw new Error("ElevenLabs API key is required");
    if (!config.agentId) throw new Error("ElevenLabs agent ID is required");
    if (!config.phoneNumberId) throw new Error("ElevenLabs phone number ID is required");
    this.config = config;
  }

  onEvent(cb: (event: NormalizedEvent) => void): void {
    this.eventCallback = cb;
  }

  verifyWebhook(_ctx: WebhookContext): WebhookVerificationResult {
    return { ok: true };
  }

  parseWebhookEvent(
    _ctx: WebhookContext,
    _options?: WebhookParseOptions,
  ): ProviderWebhookParseResult {
    return { events: [], statusCode: 200 };
  }

  async initiateCall(input: InitiateCallInput): Promise<InitiateCallResult> {
    const apiKey = this.config.apiKey;
    if (!apiKey) throw new Error("ElevenLabs API key is not configured");
    const agentId = this.config.agentId;
    if (!agentId) throw new Error("ElevenLabs agent ID is not configured");

    const taskDescription =
      (input.clientState?.message as string | undefined) ?? "Make a phone call";

    const clientData: Record<string, unknown> = {
      dynamic_variables: { task_description: taskDescription },
    };

    const language = input.clientState?.language as string | undefined;
    if (language) {
      clientData.conversation_config_override = { agent: { language } };
    }

    const body: Record<string, unknown> = {
      agent_id: agentId,
      agent_phone_number_id: this.config.phoneNumberId,
      to_number: input.to,
      conversation_initiation_client_data: clientData,
    };

    const res = await fetch("https://api.elevenlabs.io/v1/convai/twilio/outbound-call", {
      method: "POST",
      headers: {
        "xi-api-key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`ElevenLabs API error: ${res.status} ${text}`);
    }

    const data = (await res.json()) as { conversation_id?: string; call_sid?: string };
    const providerCallId = data.conversation_id ?? data.call_sid;
    if (!providerCallId) {
      throw new Error("ElevenLabs API did not return a conversation_id");
    }

    this.startPolling(input.callId, providerCallId, apiKey);

    return { providerCallId, status: "initiated" };
  }

  async hangupCall(input: HangupCallInput): Promise<void> {
    this.stopPolling(input.providerCallId);
  }

  async playTts(_input: PlayTtsInput): Promise<void> {}

  async startListening(_input: StartListeningInput): Promise<void> {}

  async stopListening(_input: StopListeningInput): Promise<void> {}

  async getCallStatus(input: GetCallStatusInput): Promise<GetCallStatusResult> {
    const apiKey = this.config.apiKey;
    if (!apiKey) {
      return { status: "unknown", isTerminal: false, isUnknown: true };
    }
    try {
      const conv = await fetchConversationStatus(apiKey, input.providerCallId);
      const isTerminal = conv.status === "done" || conv.status === "failed";
      return { status: conv.status, isTerminal };
    } catch {
      return { status: "unknown", isTerminal: false, isUnknown: true };
    }
  }

  private startPolling(callId: string, conversationId: string, apiKey: string): void {
    const intervalMs = this.config.pollIntervalMs ?? 5000;
    let answeredEmitted = false;

    const timer = setInterval(async () => {
      try {
        const conv = await fetchConversationStatus(apiKey, conversationId);

        if (!answeredEmitted && conv.status !== "failed") {
          answeredEmitted = true;
          this.emit({
            id: `${conversationId}-answered`,
            type: "call.answered",
            callId,
            providerCallId: conversationId,
            timestamp: Date.now(),
          } as NormalizedEvent);
        }

        if (conv.transcript && conv.transcript.length > 0) {
          const seen = this.seenTranscriptCounts.get(conversationId) ?? 0;
          for (let i = seen; i < conv.transcript.length; i++) {
            const entry = conv.transcript[i]!;
            this.emit({
              id: `${conversationId}-speech-${i}`,
              type: "call.speech",
              callId,
              providerCallId: conversationId,
              timestamp: Date.now(),
              transcript: entry.message,
              isFinal: true,
              confidence: 1.0,
            } as NormalizedEvent);
          }
          this.seenTranscriptCounts.set(conversationId, conv.transcript.length);
        }

        if (conv.status === "done" || conv.status === "failed") {
          this.stopPolling(conversationId);
          this.emit({
            id: `${conversationId}-ended`,
            type: "call.ended",
            callId,
            providerCallId: conversationId,
            timestamp: Date.now(),
            reason: conv.status === "failed" ? "failed" : "completed",
          } as NormalizedEvent);
        }
      } catch (err) {
        console.warn(
          `[elevenlabs-agents] Poll error for ${conversationId}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }, intervalMs);

    this.pollTimers.set(conversationId, timer);
  }

  private stopPolling(conversationId: string): void {
    const timer = this.pollTimers.get(conversationId);
    if (timer) {
      clearInterval(timer);
      this.pollTimers.delete(conversationId);
    }
    this.seenTranscriptCounts.delete(conversationId);
  }

  dispose(): void {
    for (const [, timer] of this.pollTimers) {
      clearInterval(timer);
    }
    this.pollTimers.clear();
    this.seenTranscriptCounts.clear();
  }

  private emit(event: NormalizedEvent): void {
    if (this.eventCallback) {
      this.eventCallback(event);
    }
  }
}
