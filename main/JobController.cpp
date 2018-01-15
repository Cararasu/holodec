#include "JobController.h"

namespace holodec{

	uint64_t JobController::queue_job (Job&& job) {
		std::unique_lock<std::mutex> mlock (mutex);
		job.id = ++counter;
		jobs.push (std::move (job));
		++jobs_to_do;
		mlock.unlock();
		cond.notify_one();
		return job.id;
	}
	Job JobController::get_next_job() {
		std::unique_lock<std::mutex> mlock (mutex);
		cond.wait (mlock, [this](){return !jobs.empty() || (!jobs.empty() && end_on_empty.load()) || !running.load();});
		
		if(!running.load() || (jobs.empty() && end_on_empty.load()))
			return Job();
			
		auto job = jobs.front();
		jobs.pop();
		return job;
	}

	void JobController::get_next_job (Job& job) {
		std::unique_lock<std::mutex> mlock (mutex);
		cond.wait (mlock, [this](){return !jobs.empty() || (jobs.empty() && end_on_empty.load()) || !running.load();});
		
		if(!running.load() || (jobs.empty() && end_on_empty.load())){
			job = Job();
			return;
		}
		job = jobs.front();
		jobs.pop();
	}
	void JobController::start_job_loop(JobContext context){
		Job nextJob;
		++executors_running;
		
		while(running.load()){
			
			nextJob = get_next_job();
			
			if(nextJob.func){
				nextJob.func(context);
				int todo = --jobs_to_do;
				if(!todo)
					end_cond.notify_all();
				printf("Jobs ToDo %d\n", todo);
				printf("Jobs in Queue %d\n", jobs.size());
			}
		}
		if(!--executors_running)
			end_cond.notify_all();
	}
	void JobController::stop_jobs(){
		running.store(false);
		cond.notify_all();
	}

	void JobController::wait_for_finish(){
		end_on_empty.store(true);
		std::unique_lock<std::mutex> mlock (end_mutex);
		end_cond.wait (mlock, [this](){return jobs_to_do == 0;});
		printf("All Finished\n");
		fflush(stdout);
	}
	void JobController::wait_for_exit(){
		running.store(false);
		cond.notify_all();
		std::unique_lock<std::mutex> mlock (end_mutex);
		end_cond.wait (mlock, [this](){return executors_running == 0;});
		printf("All Finished\n");
	}
}