/**
 * BangAuth — NATS Event Publisher
 *
 * Publishes authentication events to NATS for constellation-wide coordination.
 * When a user successfully authenticates, we broadcast an event so other
 * services can react (provision twins, log activity, update metrics, etc.).
 *
 * // Why: In a microservices constellation, services need to know when users
 * // log in. NATS provides lightweight, reliable pub/sub messaging. The auth
 * // service publishes events; other services subscribe and react.
 *
 * @module adapters/nats-publisher
 */

import { connect, NatsConnection, type ConnectionOptions } from 'nats';

/**
 * Event payload for user.authenticated.
 */
export interface UserAuthenticatedEvent {
  userId: string;
  email: string;
  twinId: string;
  timestamp: string;
  mfaUsed: boolean;
}

/**
 * NATS event publisher.
 */
export class NatsPublisher {
  private nc: NatsConnection | null = null;
  private readonly natsUrl: string;

  constructor(natsUrl?: string) {
    this.natsUrl = natsUrl || process.env.NATS_URL || 'nats://localhost:4222';
  }

  /**
   * Connect to NATS server.
   *
   * // Why: Lazy connection — we don't connect until the first publish.
   * // This allows the service to start even if NATS is temporarily unavailable.
   */
  private async ensureConnected(): Promise<NatsConnection> {
    if (this.nc) {
      return this.nc;
    }

    try {
      console.log(`🔌 Connecting to NATS at ${this.natsUrl}...`);
      this.nc = await connect({
        servers: this.natsUrl,
        name: 'bangauth',
      });
      console.log('✅ Connected to NATS');
      return this.nc;
    } catch (err) {
      console.error('❌ Failed to connect to NATS:', err);
      throw err;
    }
  }

  /**
   * Publish a user.authenticated event.
   *
   * // Why: This is the canonical "user logged in" event. Other services
   * // subscribe to this channel to know when to provision twins, update
   * // access logs, send analytics, etc.
   *
   * @param event - The authentication event payload.
   */
  async publishUserAuthenticated(event: UserAuthenticatedEvent): Promise<void> {
    try {
      const nc = await this.ensureConnected();
      const subject = 'user.authenticated';
      const data = JSON.stringify(event);

      nc.publish(subject, new TextEncoder().encode(data));
      console.log(`📡 Published ${subject}: ${event.email} → ${event.twinId}`);
    } catch (err) {
      // Why: NATS failure shouldn't block authentication. Log the error and
      // continue — the user is authenticated even if the event doesn't go out.
      console.error('❌ Failed to publish user.authenticated event:', err);
    }
  }

  /**
   * Close the NATS connection.
   *
   * // Why: Called during graceful shutdown to drain pending messages.
   */
  async close(): Promise<void> {
    if (this.nc) {
      await this.nc.drain();
      console.log('🔌 NATS connection closed');
      this.nc = null;
    }
  }
}
