package handler

import "testing"

type recordingJobCanceller struct {
	conversationID string
	userID         string
	calls          int
}

func (r *recordingJobCanceller) CancelConversationJobs(conversationID, userID string) int {
	r.conversationID = conversationID
	r.userID = userID
	r.calls++
	return 1
}

func TestCancelConversationWorkCallsJobCanceller(t *testing.T) {
	jobs := &recordingJobCanceller{}
	cancelled, jobsCancelled := cancelConversationWork(nil, jobs, "conv-1", "user-1")
	if cancelled != 0 || jobsCancelled != 1 ||
		jobs.calls != 1 || jobs.conversationID != "conv-1" || jobs.userID != "user-1" {
		t.Fatalf("会话 Job 未取消: %+v", jobs)
	}
}
