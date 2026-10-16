"""Explicit source-level effect contracts, independent of experiment labels.

Checks are named and scoped. A contract does not claim whole-task correctness.
The tau contracts describe pinned original tools, including their asynchronous
request semantics; they do not demand production payment/airline settlement.
"""
from collections import Counter
from copy import deepcopy
import hashlib
import json
import posixpath
from .collectors import canonical, durable_content, semantic_fs_diff

READ_FILES={'read_text_file','read_file','read_multiple_files','list_directory','list_directory_with_sizes',
            'directory_tree','get_file_info','list_allowed_directories','search_files','read_media_file'}
FILE_TOOLS=READ_FILES|{'write_file','create_directory','move_file','edit_file'}
TAU_READ={'find_user_id_by_name_zip','find_user_id_by_email','get_order_details','get_product_details','get_user_details',
          'get_reservation_details','list_all_product_types','list_all_airports','search_direct_flight','search_onestop_flight',
          'calculate','think','transfer_to_human_agents'}
TAU_MUTATE={'exchange_delivered_order_items','return_delivered_order_items','modify_pending_order_items',
            'cancel_pending_order','modify_pending_order_address','modify_user_address','modify_pending_order_payment',
            'book_reservation','cancel_reservation','update_reservation_flights','update_reservation_baggages',
            'update_reservation_passengers','send_certificate'}


def check(name, okay, reason=None):
    return {'name':name,'verdict':'Uncertain' if okay is None else 'Consistent' if okay else 'Inconsistent',
            'reason':reason or name}


def snapshots(event):
    a,b=event.get('state_before'),event.get('state_after')
    if not a or not b:return None,None,'missing_state_observation'
    if not a.get('complete') or not b.get('complete') or a.get('issues') or b.get('issues'):
        return None,None,'incomplete_or_unstable_state_observation'
    return a['objects'],b['objects'],None


def path(value):
    if not isinstance(value,str):raise ValueError('path_type')
    p=posixpath.normpath(value)
    if p.startswith('/') or p=='..' or p.startswith('../'):raise ValueError('path_scope')
    return p


def filesystem(event):
    tool,args=event['tool'],event['arguments']
    before,after,why=snapshots(event)
    if why:return [check('filesystem_effect',None,why)]
    changes=semantic_fs_diff(before,after)
    error=event.get('result',{}).get('isError',False)
    if tool in READ_FILES:
        return [check('filesystem_read_has_no_content_side_effect',not changes)]
    if error:
        return [check('failed_filesystem_operation_effect',True if not changes else None,
                      'honest_error_without_content_change' if not changes else 'partial_error_effect_semantics')]
    try:
        if tool=='write_file':
            target=path(args['path']);data=args['content'].encode('utf-8')
            actual=after.get(target,{})
            expected=hashlib.sha256(data).hexdigest()
            return [check('write_full_content',actual.get('kind')=='file' and actual.get('sha256')==expected and actual.get('bytes')==len(data)),
                    check('write_resource_scope',set(changes)<={target})]
        if tool=='create_directory':
            target=path(args['path'])
            if event['state_after'].get('directory_coverage') is False:
                return [check('directory_existence',None,'historical_snapshot_did_not_observe_directories')]
            permitted=set();p=target
            while p not in ('.',''):
                permitted.add(p);p=posixpath.dirname(p)
            return [check('directory_existence',target=='.' or after.get(target,{}).get('kind')=='directory'),
                    check('mkdir_resource_scope',set(changes)<=permitted and all(after.get(p,{}).get('kind')=='directory' for p in changes))]
        if tool=='move_file':
            src,dst=path(args['source']),path(args['destination'])
            if src==dst:return [check('move_same_object_no_content_change',not changes)]
            subtree={p:v for p,v in before.items() if p==src or p.startswith(src+'/')}
            if not subtree:return [check('move_source_identity',None,'source_object_not_observed')]
            ok=all(durable_content(after.get(dst+p[len(src):]))==durable_content(v) and p not in after for p,v in subtree.items())
            allowed=set(subtree)|{dst+p[len(src):] for p in subtree}
            return [check('move_source_to_target',ok),check('move_resource_scope',set(changes)<=allowed)]
        if tool=='edit_file':
            target=path(args['path']);content=before.get(target,{}).get('text')
            if content is None:return [check('edit_content',None,'missing_pre_edit_text')]
            content=content.replace('\r\n','\n')
            for edit in args['edits']:
                old,new=edit['oldText'].replace('\r\n','\n'),edit['newText'].replace('\r\n','\n')
                if old not in content:return [check('edit_content',None,'fuzzy_edit_semantics_not_supported')]
                content=content.replace(old,new,1)
            if args.get('dryRun'):return [check('edit_dry_run_no_content_change',not changes)]
            data=content.encode();actual=after.get(target,{})
            return [check('edit_content',actual.get('sha256')==hashlib.sha256(data).hexdigest() and actual.get('bytes')==len(data)),
                    check('edit_resource_scope',set(changes)<={target})]
    except (KeyError,ValueError,TypeError,AttributeError):return [check('filesystem_semantics',None,'unsupported_filesystem_arguments')]
    return [check('filesystem_semantics',None,'unregistered_filesystem_tool')]


def tau(event):
    tool,args=event['tool'],event['arguments']
    before,after,why=snapshots(event)
    if why:return [check('business_effect',None,why)]
    changed={k for k in set(before)|set(after) if canonical(before.get(k))!=canonical(after.get(k))}
    if tool in TAU_READ:return [check('tau_read_no_state_mutation',not changed)]
    if tool not in TAU_MUTATE:return [check('business_semantics',None,'unregistered_tau_tool')]
    result=event.get('result',{})
    if result.get('isError'):
        return [check('tau_failed_call_effect',True if not changed else None,
                      'honest_error_without_state_change' if not changed else 'partial_error_effect_semantics')]
    try:
        raw='\n'.join(r['text'] for r in result.get('content',[]) if r.get('type')=='text')
        returned=json.loads(raw)
        if not isinstance(returned,dict):return [check('business_return_schema',None,'non_record_business_return')]
        keyfield,table=(('order_id','orders') if tool in {'exchange_delivered_order_items','return_delivered_order_items','modify_pending_order_items',
               'cancel_pending_order','modify_pending_order_address','modify_pending_order_payment'} else ('user_id','users') if tool in {'modify_user_address','send_certificate'} else ('reservation_id','reservations'))
        key=args.get(keyfield,returned.get(keyfield));locator=table+'/'+str(key)
        old,new=before.get(locator,{}),after.get(locator,{})
        checks=[check('native_return_matches_actual_record',canonical(returned)==canonical(new))]
        user_id=old.get('user_id',new.get('user_id',args.get('user_id')))
        userkey='users/'+str(user_id);userbefore=before.get(userkey,{});userafter=after.get(userkey,{})
        allowed={locator}
        expectations={}
        if tool in ('modify_pending_order_address','modify_user_address'):
            expectations['address']={k:args[k] for k in ('address1','address2','city','state','country','zip')}
        elif tool=='return_delivered_order_items':
            expectations={'status':'return requested','return_items':sorted(args['item_ids']), 'return_payment_method_id':args['payment_method_id']}
        elif tool=='exchange_delivered_order_items':
            expectations={'status':'exchange requested','exchange_items':sorted(args['item_ids']),
                          'exchange_new_items':sorted(args['new_item_ids']),'exchange_payment_method_id':args['payment_method_id']}
            diff=0
            for a,b in zip(args['item_ids'],args['new_item_ids']):
                item=next(i for i in old['items'] if i['item_id']==a)
                diff+=before['products/'+item['product_id']]['variants'][b]['price']-item['price']
            expectations['exchange_price_difference']=round(diff,2)
        elif tool=='cancel_reservation':
            expectations={'status':'cancelled','payment_history':old['payment_history']+
                          [{'payment_id':p['payment_id'],'amount':-p['amount']} for p in old['payment_history']]}
        elif tool=='update_reservation_passengers':expectations={'passengers':args['passengers']}
        elif tool=='update_reservation_baggages':
            expectations={k:args[k] for k in ('total_baggages','nonfree_baggages')}
            cost=50*max(0,args['nonfree_baggages']-old['nonfree_baggages'])
            expectations['payment_history']=old['payment_history']+([{'payment_id':args['payment_id'],'amount':cost}] if cost else [])
            if userbefore['payment_methods'][args['payment_id']]['source']=='gift_card':
                allowed.add(userkey)
                expected_user=deepcopy(userbefore);expected_user['payment_methods'][args['payment_id']]['amount']-=cost
                checks.append(check('baggage_payment_effect',canonical(expected_user)==canonical(userafter)))
        elif tool=='update_reservation_flights':
            flights=deepcopy(args['flights']);cost=0
            for flight in flights:
                prior=next((f for f in old['flights'] if f['flight_number']==flight['flight_number'] and f['date']==flight['date'] and args['cabin']==old['cabin']),None)
                if prior:flight.update({k:prior[k] for k in ('price','origin','destination')})
                else:
                    info=before['flights/'+flight['flight_number']]
                    flight.update(price=info['dates'][flight['date']]['prices'][args['cabin']],origin=info['origin'],destination=info['destination'])
                cost+=flight['price']*len(old['passengers'])
            cost-=sum(f['price'] for f in old['flights'])*len(old['passengers'])
            expectations={'flights':flights,'payment_history':old['payment_history']+([{'payment_id':args['payment_id'],'amount':cost}] if cost else [])}
            # Pinned upstream does not immediately change flights inventory or
            # reservation.cabin; do not invent those as required state updates.
            if userbefore['payment_methods'][args['payment_id']]['source']=='gift_card':
                allowed.add(userkey);u=deepcopy(userbefore);u['payment_methods'][args['payment_id']]['amount']-=cost
                checks.append(check('flight_payment_effect',canonical(u)==canonical(userafter)))
        elif tool=='modify_pending_order_items':
            items=deepcopy(old['items']);diff=0
            for a,b in zip(args['item_ids'],args['new_item_ids']):
                item=next(i for i in old['items'] if i['item_id']==a)
                diff+=before['products/'+item['product_id']]['variants'][b]['price']-item['price']
            for a,b in zip(args['item_ids'],args['new_item_ids']):
                item=next(i for i in items if i['item_id']==a);variant=before['products/'+item['product_id']]['variants'][b]
                item.update(item_id=b,price=variant['price'],options=variant['options'])
            expectations={'items':items,'status':'pending (item modified)','payment_history':old['payment_history']+
                          [{'transaction_type':'payment' if diff>0 else 'refund','amount':abs(diff),'payment_method_id':args['payment_method_id']}]}
            if userbefore['payment_methods'][args['payment_method_id']]['source']=='gift_card':
                allowed.add(userkey);u=deepcopy(userbefore);p=u['payment_methods'][args['payment_method_id']]
                p['balance']=round(p['balance']-diff,2);checks.append(check('item_payment_effect',canonical(u)==canonical(userafter)))
        elif tool=='cancel_pending_order':
            expectations={'status':'cancelled','cancel_reason':args['reason']}
            # Verify refund entries and actual gift-card balance, below via
            # explicit source contract, not an assumption of external settlement.
            history=deepcopy(old['payment_history']);u=deepcopy(userbefore)
            for payment in old['payment_history']:
                history.append(dict(payment,transaction_type='refund'))
                pid=payment['payment_method_id']
                if 'gift_card' in pid:
                    p=u['payment_methods'][pid];p['balance']=round(p['balance']+payment['amount'],2)
            expectations['payment_history']=history
            if u!=userbefore:allowed.add(userkey)
            checks.append(check('cancel_refund_state',canonical(u)==canonical(userafter)))
        elif tool=='book_reservation':
            expectations={k:args[k] for k in ('user_id','origin','destination','flight_type','cabin','passengers','total_baggages','nonfree_baggages','insurance') if k in args}
            flights=deepcopy(args['flights']);cost=0
            for flight in flights:
                info=before['flights/'+flight['flight_number']]
                flight.update(price=info['dates'][flight['date']]['prices'][args['cabin']],origin=info['origin'],destination=info['destination'])
                cost+=flight['price']*len(args['passengers'])
            cost+=50*args['nonfree_baggages']+(30*len(args['passengers']) if args['insurance']=='yes' else 0)
            checks.append(check('booking_fare_matches_payment',cost==sum(p['amount'] for p in args['payment_methods'])))
            expected_user=deepcopy(userbefore)
            for payment in args['payment_methods']:
                pid=payment['payment_id'];method=expected_user['payment_methods'][pid]
                if method['source']=='gift_card':method['amount']-=payment['amount']
                elif method['source']=='certificate':del expected_user['payment_methods'][pid]
            expected_user['reservations'].append(key);allowed.add(userkey)
            checks.append(check('booking_user_and_payment_state',canonical(expected_user)==canonical(userafter)))
            expectations.update(reservation_id=key,flights=flights,payment_history=args['payment_methods'],created_at='2024-05-15T15:00:00')
            checks.append(check('booking_record_created',not old))
            # The pinned upstream implementation leaves seat inventory unchanged.
        else:return checks+[check('business_effect_contract',None,'registered_tool_effect_contract_partial')]
        expected=deepcopy(old);expected.update(expectations)
        checks.append(check('business_record_transition',canonical(expected)==canonical(new)))
        checks.append(check('business_resource_scope',changed<=allowed))
        return checks
    except (KeyError,ValueError,TypeError,StopIteration,IndexError):
        return [check('business_semantics',None,'unsupported_business_record_or_arguments')]
