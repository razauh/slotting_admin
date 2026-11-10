set timezone='UTC';

select tenant_id, currency_code,
       sum(case when direction = 'DEBIT' then amount_minor_units else 0 end) as debits,
       sum(case when direction = 'CREDIT' then amount_minor_units else 0 end) as credits
from public.ledger_leg
group by tenant_id, currency_code
having sum(case when direction = 'DEBIT' then amount_minor_units else 0 end)
    <> sum(case when direction = 'CREDIT' then amount_minor_units else 0 end);

select w.tenant_id, w.currency_code, w.balance_minor_units,
       coalesce(sum(case when l.direction = 'CREDIT' then l.amount_minor_units
                         when l.direction = 'DEBIT' then -l.amount_minor_units end), 0) as derived
from public.wallet_projection w
left join public.ledger_leg l on l.tenant_id = w.tenant_id and l.currency_code = w.currency_code
group by w.tenant_id, w.currency_code, w.balance_minor_units
having w.balance_minor_units <> coalesce(sum(case when l.direction = 'CREDIT' then l.amount_minor_units
                                                  when l.direction = 'DEBIT' then -l.amount_minor_units end), 0);

select tenant_id, game_id, min(sequence_id) as min_sequence, max(sequence_id) as max_sequence,
       count(*) as event_count
from public.game_event_journal
group by tenant_id, game_id
having max(sequence_id) - min(sequence_id) + 1 <> count(*);

select s.settlement_id
from public.game_bet_settlement s
left join public.game_accepted_bet b on b.bet_id = s.bet_id
where b.bet_id is null;

select tenant_id, command_id, count(*) as receipt_count
from public.game_command_receipt
group by tenant_id, command_id
having count(*) > 1;

select 'delivery' as source, d.event_id::text as reference, d.tenant_id, d.status as state, d.created_at
from public.admin_outbox_delivery d
where (d.status in ('PENDING', 'LEASED', 'QUARANTINED') and d.next_attempt_at < now() - interval '5 minutes')
   or (d.status = 'LEASED' and d.lease_expires_at < now())
union all
select 'event', e.event_id::text, e.tenant_id, 'PENDING', e.created_at
from public.admin_outbox_event e
where e.published_at is null and e.created_at < now() - interval '5 minutes';

select i.tenant_id, i.event_id::text as event_id, i.consumer_name, i.status, i.attempt_count, i.lease_expires_at
from public.admin_inbox_consumer i
where (i.status in ('RECEIVED', 'PROCESSING', 'FAILED', 'QUARANTINED')
       and i.processed_at is null and (i.lease_expires_at is null or i.lease_expires_at < now()))
   or (i.status = 'PROCESSING' and i.lease_expires_at < now());

select 'commitment_without_reveal' as violation, c.commitment_id::text as reference, c.tenant_id
from public.game_fairness_commitment c
left join public.game_fairness_reveal r on r.commitment_id = c.commitment_id
where c.status = 'REVEALED' and r.reveal_id is null
union all
select 'reveal_without_commitment', r.reveal_id::text, r.tenant_id
from public.game_fairness_reveal r
left join public.game_fairness_commitment c on c.commitment_id = r.commitment_id
where c.commitment_id is null
union all
select 'reveal_not_verified', r.reveal_id::text, r.tenant_id
from public.game_fairness_reveal r
where r.verification_status <> 'VERIFIED'
union all
select 'commitment_hash_invalid', c.commitment_id::text, c.tenant_id
from public.game_fairness_commitment c
where length(c.commitment_hash) <> 64;
