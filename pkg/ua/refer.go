package ua

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/ghettovoice/gosip/sip"
	"github.com/jen94/go-sip-ua/pkg/account"
	"github.com/jen94/go-sip-ua/pkg/auth"
)

type ReferTo string

func (callId ReferTo) String() string {
	return fmt.Sprintf("%s: %s", callId.Name(), callId.Value())
}

func (callId *ReferTo) Name() string { return "Refer-To" }

func (callId ReferTo) Value() string { return string(callId) }

func (callId *ReferTo) Clone() sip.Header {
	return callId
}

func (callId *ReferTo) Equals(other interface{}) bool {
	if h, ok := other.(ReferTo); ok {
		if callId == nil {
			return false
		}

		return *callId == h
	}
	if h, ok := other.(*ReferTo); ok {
		if callId == h {
			return true
		}
		if callId == nil && h != nil || callId != nil && h == nil {
			return false
		}

		return *callId == *h
	}

	return false
}

type ReferredBy string

func (callId ReferredBy) String() string {
	return fmt.Sprintf("%s: %s", callId.Name(), callId.Value())
}

func (callId *ReferredBy) Name() string { return "Referred-By" }

func (callId ReferredBy) Value() string { return string(callId) }

func (callId *ReferredBy) Clone() sip.Header {
	return callId
}

func (callId *ReferredBy) Equals(other interface{}) bool {
	if h, ok := other.(ReferredBy); ok {
		if callId == nil {
			return false
		}

		return *callId == h
	}
	if h, ok := other.(*ReferredBy); ok {
		if callId == h {
			return true
		}
		if callId == nil && h != nil || callId != nil && h == nil {
			return false
		}

		return *callId == *h
	}

	return false
}

type Refer struct {
	ua         *UserAgent
	timer      *time.Timer
	profile    *account.Profile
	authorizer *auth.ClientAuthorizer
	recipient  sip.SipUri
	request    *sip.Request
	ctx        context.Context
	cancel     context.CancelFunc
	data       interface{}
}

func NewRefer(ua *UserAgent, profile *account.Profile, recipient sip.SipUri, data interface{}) *Refer {
	r := &Refer{
		ua:        ua,
		profile:   profile,
		recipient: recipient,
		request:   nil,
		data:      data,
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return r
}

func (r *Refer) SendRefer(expires uint32, headers []sip.Header, fromTag string, toTag string, callID string, referTo string, referredBy string, cseqVal int) error {

	ua := r.ua
	profile := r.profile
	recipient := r.recipient

	from := &sip.Address{
		Uri:    profile.URI,
		Params: sip.NewParams().Add("tag", sip.String{Str: fromTag}),
	}

	to := &sip.Address{
		Uri:    profile.URI,
		Params: sip.NewParams().Add("tag", sip.String{Str: toTag}),
	}

	contact := profile.Contact()

	if r.request == nil || expires == 0 {
		callid := sip.CallID(callID)
		request, err := ua.buildRequest(sip.REFER, from, to, contact, recipient, profile.Routes, &callid)
		if err != nil {
			ua.Log().Errorf("Refer: err = %v", err)
			return err
		}
		expiresHeader := sip.Expires(expires)
		(*request).AppendHeader(&expiresHeader)
		r.request = request
		cseq, _ := (*r.request).CSeq()
		if cseq.SeqNo < uint32(cseqVal) {
			cseq.SeqNo = uint32(cseqVal)
			cseq.MethodName = sip.REFER
		}
	} else {
		cseq, _ := (*r.request).CSeq()
		cseq.SeqNo++
		cseq.MethodName = sip.REFER

		(*r.request).RemoveHeader("Expires")
		// replace Expires header.
		expiresHeader := sip.Expires(expires)
		(*r.request).AppendHeader(&expiresHeader)
	}

	referToHeader := ReferTo(referTo)
	(*r.request).AppendHeader(&referToHeader)

	referredByHeader := ReferredBy(referredBy)
	(*r.request).AppendHeader(&referredByHeader)

	for _, header := range headers {
		(*r.request).AppendHeader(header)
	}

	if profile.AuthInfo != nil && r.authorizer == nil {
		r.authorizer = auth.NewClientAuthorizer(profile.AuthInfo.AuthUser, profile.AuthInfo.Password)
	}
	resp, err := ua.RequestWithContext(r.ctx, *r.request, r.authorizer, true, 1)

	if err != nil {
		ua.Log().Errorf("Request [%s] failed, err => %v", sip.REFER, err)

		var code sip.StatusCode
		var reason string
		if _, ok := err.(*sip.RequestError); ok {
			reqErr := err.(*sip.RequestError)
			code = sip.StatusCode(reqErr.Code)
			reason = reqErr.Reason
		} else {
			code = 500
			reason = err.Error()
		}

		state := account.ReferState{
			Account:    profile,
			Response:   nil,
			StatusCode: sip.StatusCode(code),
			Reason:     reason,
			Expiration: 0,
			UserData:   r.data,
		}

		ua.Log().Debugf("Request [%s], has error %v, state => %v", sip.REFER, err, state)

	}
	if resp != nil {
		stateCode := resp.StatusCode()
		ua.Log().Debugf("%s resp %d => %s", sip.REFER, stateCode, resp.String())

		var expires uint32 = 0
		hdrs := resp.GetHeaders("Expires")
		if len(hdrs) > 0 {
			expires = uint32(*(hdrs[0]).(*sip.Expires))
		} else {
			hdrs = resp.GetHeaders("Contact")
			if len(hdrs) > 0 {
				if cexpires, cexpirescok := (hdrs[0].(*sip.ContactHeader)).Params.Get("expires"); cexpirescok {
					cexpiresint, _ := strconv.Atoi(cexpires.String())
					expires = uint32(cexpiresint)
				}
			}
		}
		state := account.ReferState{
			Account:    profile,
			Response:   resp,
			StatusCode: resp.StatusCode(),
			Reason:     resp.Reason(),
			Expiration: expires,
			UserData:   r.data,
		}
		if expires > 0 {
			go func() {
				if r.timer == nil {
					r.timer = time.NewTimer(time.Second * time.Duration(expires-10))
				} else {
					r.timer.Reset(time.Second * time.Duration(expires-10))
				}
				select {
				case <-r.timer.C:
					r.SendRefer(expires, headers, fromTag, toTag, callID, referTo, referredBy, cseqVal)
				case <-r.ctx.Done():
					return
				}
			}()
		} else if expires == 0 {
			if r.timer != nil {
				r.timer.Stop()
				r.timer = nil
			}
			r.request = nil
		}

		ua.Log().Debugf("Request [%s], response: state => %v", sip.REFER, state)

	}

	return nil
}

func (r *Refer) Stop() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.cancel()
}
