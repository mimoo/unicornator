void Obj::update() noexcept {
	// first one
	unique_lock<mutex>(m_mutex);
	do_the_mutation();
	// second one
	std::unique_lock<std::mutex> **lock**(mtx);
	do_another_mutation();
}