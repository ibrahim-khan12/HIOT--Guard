"""Keep GNS3 console replies small while retaining complete capture receipts."""
import pilot_worker


def get_status(handler):
    if handler.headers.get('Authorization') != 'Bearer ' + pilot_worker.TOKEN:
        return handler.respond(403, {})
    state = dict(pilot_worker.STATE)
    receipts = list(state.pop('receipts', []))
    if handler.path == '/state':
        state['receipt_ids'] = [row['session_id'] for row in receipts]
        return handler.respond(200, state)
    if handler.path.startswith('/receipt/'):
        requested = handler.path.removeprefix('/receipt/')
        for row in receipts:
            if row['session_id'] == requested:
                return handler.respond(200, row)
    return handler.respond(404, {})


pilot_worker.API.do_GET = get_status
