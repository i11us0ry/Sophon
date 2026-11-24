package handler

import "sophon/internal/task"

type conversationJobCanceller interface {
	CancelConversationJobs(conversationID, userID string) int
}

func cancelConversationWork(
	manager *task.Manager,
	jobs conversationJobCanceller,
	conversationID string,
	userID string,
) (int, int) {
	cancelled := 0
	jobsCancelled := 0
	if manager != nil {
		cancelled = manager.CancelConversation(conversationID, userID)
	}
	if jobs != nil {
		jobsCancelled = jobs.CancelConversationJobs(conversationID, userID)
	}
	return cancelled, jobsCancelled
}
