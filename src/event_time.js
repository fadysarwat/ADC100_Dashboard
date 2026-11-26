/* When did an event really happen?
   A device that was offline keeps its events and sends them later with
   queued:true and age_s = seconds since the event happened. The device clock
   is not trusted (it is 1970 after a reboot without NTP), so the server works
   out the time from its own clock: occurred_at = now - age_s. */

const MAX_AGE_S = 7 * 24 * 3600;   // a bogus value can never push a log entry further back than a week

/* Seconds to subtract from NOW() for this event. 0 for a live event. */
function eventAgeSeconds(payload) {
    if (!payload || payload.queued !== true) return 0;
    const age = Number(payload.age_s);
    if (!Number.isFinite(age) || age < 0) return 0;
    return Math.min(Math.floor(age), MAX_AGE_S);
}

module.exports = { eventAgeSeconds, MAX_AGE_S };
