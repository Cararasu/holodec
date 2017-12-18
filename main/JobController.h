#ifndef JOBCONTROLLER_H
#define JOBCONTROLLER_H

#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>

namespace holodec {

	struct JobContext {
		uint32_t threadId;
	};
	struct Job {
		std::function<void (JobContext) > func;
	};

	struct JobController {
		std::queue<Job> jobs;
		
		std::mutex mutex;
		std::condition_variable cond;
		
		std::mutex end_mutex;
		std::condition_variable end_cond;
		
		std::atomic_int executors_running = 0;
		std::atomic_int jobs_to_do = 0;
		
		std::atomic_bool end_on_empty = false;
		std::atomic_bool running = true;

	public:
		JobController() = default;
		
		void queue_job (const Job& job);
		void queue_job (Job&& job);
		
		Job get_next_job();
		void get_next_job (Job& job);
		
		void start_job_loop (JobContext context);

		void wait_for_finish();
		void wait_for_exit();

		void stop_jobs();

	};

}
#endif // JOBCONTROLLER_H
