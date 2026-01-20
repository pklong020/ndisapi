// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  fastio_packet_filter.h 
/// Abstract: Multi-adapter packet filter class declaration
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>

namespace ndisapi
{
	inline constexpr size_t fast_io_size = 0x300000;
	inline constexpr uint32_t fast_io_packets_num = (fast_io_size - sizeof(FAST_IO_SECTION_HEADER)) / sizeof(
		INTERMEDIATE_BUFFER);
	inline constexpr size_t maximum_packet_block = 2048 * 3;

	// --------------------------------------------------------------------------------
	/// <summary>
	/// multi-adapter winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class multi_fastio_packet_filter final : public CNdisApi
	{
	public:
		enum class packet_action
		{
			pass,
			drop,
			revert
		};

	private:
		enum class filter_state
		{
			stopped,
			starting,
			running,
			stopping
		};

		using request_storage_type_t = std::aligned_storage_t<
			sizeof(PINTERMEDIATE_BUFFER) * maximum_packet_block, 0x1000>;
		using fast_io_storage_type_t = std::aligned_storage_t<fast_io_size, 0x1000>;

		// 为每个适配器定义资源结构
		struct adapter_resources {
			size_t adapter_index;
			std::unique_ptr<INTERMEDIATE_BUFFER[]> packet_buffer;
			std::unique_ptr<request_storage_type_t> write_adapter_request_ptr;
			std::unique_ptr<request_storage_type_t> write_mstcp_request_ptr;
			std::unique_ptr<fast_io_storage_type_t[]> fast_io_ptr;
			std::thread working_thread;
			std::atomic<filter_state> state;
			bool initialized;

			adapter_resources() : 
				state(filter_state::stopped), 
				initialized(false),
				adapter_index(0) 
			{
			}
		};

		explicit multi_fastio_packet_filter(const bool wait_on_poll = false) :
			wait_on_poll_(wait_on_poll)
		{
			initialize_network_interfaces();
		}

	public:
		~multi_fastio_packet_filter() override { stop_all_filters(); }

		multi_fastio_packet_filter(const multi_fastio_packet_filter& other) = delete;
		multi_fastio_packet_filter(multi_fastio_packet_filter&& other) noexcept = delete;
		multi_fastio_packet_filter& operator=(const multi_fastio_packet_filter& other) = delete;
		multi_fastio_packet_filter& operator=(multi_fastio_packet_filter&& other) noexcept = delete;

		// ********************************************************************************
		/// <summary>
		/// Constructs multi_fastio_packet_filter
		/// </summary>
		/// <param name="in">incoming packets handling routine</param>
		/// <param name="out">outgoing packet handling routine</param>
		/// <returns></returns>
		// ********************************************************************************
		template <typename F1, typename F2>
		multi_fastio_packet_filter(F1 in, F2 out, const bool sleep_on_poll = false):
			multi_fastio_packet_filter(sleep_on_poll)
		{
			filter_incoming_packet_ = in;
			filter_outgoing_packet_ = out;
		}

		// ********************************************************************************
		/// <summary>
		/// Updates available network interfaces. Should be called when the filter is inactive. 
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool reconfigure();
		
		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering on single adapter
		/// </summary>
		/// <param name="adapter">network interface index to filter</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filter(size_t adapter);
		
		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering on multiple adapters
		/// </summary>
		/// <param name="adapters">vector of network interface indices to filter</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filters(const std::vector<size_t>& adapters);
		
		// ********************************************************************************
		/// <summary>
		/// Stops packet filtering on specific adapter
		/// </summary>
		/// <param name="adapter">adapter index to stop</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool stop_filter(size_t adapter);
		
		// ********************************************************************************
		/// <summary>
		/// Stops all packet filtering
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool stop_all_filters();
		
		// ********************************************************************************
		/// <summary>
		/// Checks if adapter is currently being filtered
		/// </summary>
		/// <param name="adapter">adapter index to check</param>
		/// <returns>true if filtering, false otherwise</returns>
		// ********************************************************************************
		bool is_filtering(size_t adapter) const;
		
		// ********************************************************************************
		/// <summary>
		/// Queries the list of the names for the available network interfaces
		/// </summary>
		/// <returns>list of network adapters friendly names</returns>
		// ********************************************************************************
		std::vector<std::string> get_interface_names_list() const;

		// ********************************************************************************
		/// <summary>
		/// Queries the list of the available network interfaces
		/// </summary>
		/// <returns>vector of available network adapters</returns>
		// ********************************************************************************
		const std::vector<std::unique_ptr<network_adapter>>& get_interface_list() const;

		// ********************************************************************************
		/// <summary>
		/// Returns current filter state for specific adapter
		/// </summary>
		/// <param name="adapter">adapter index</param>
		/// <returns>current filter state for the adapter</returns>
		// ********************************************************************************
		[[nodiscard]] filter_state get_filter_state(size_t adapter) const;

		// ********************************************************************************
		/// <summary>
		/// Returns all currently filtered adapters
		/// </summary>
		/// <returns>vector of filtered adapter indices</returns>
		// ********************************************************************************
		[[nodiscard]] std::vector<size_t> get_filtered_adapters() const;

	private:
		// ********************************************************************************
		/// <summary>
		/// Working thread routine for specific adapter
		/// </summary>
		/// <param name="adapter_idx">adapter index</param>
		// ********************************************************************************
		void filter_working_thread(size_t adapter_idx);
		
		// ********************************************************************************
		/// <summary>
		/// Initializes available network interface list
		/// </summary>
		// ********************************************************************************
		void initialize_network_interfaces();
		
		// ********************************************************************************
		/// <summary>
		/// Initialize interface and associated data structures required for packet filtering
		/// </summary>
		/// <param name="adapter_idx">adapter index</param>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool init_filter(size_t adapter_idx);
		
		// ********************************************************************************
		/// <summary>
		/// Release interface and associated data structures required for packet filtering
		/// </summary>
		/// <param name="adapter_idx">adapter index</param>
		// ********************************************************************************
		void release_filter(size_t adapter_idx);
		
		// ********************************************************************************
		/// <summary>
		/// Gets adapter resources or creates new ones
		/// </summary>
		/// <param name="adapter_idx">adapter index</param>
		/// <returns>pointer to adapter resources</returns>
		// ********************************************************************************
		adapter_resources* get_or_create_adapter_resources(size_t adapter_idx);

		/// <summary>outgoing packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_outgoing_packet_ = nullptr;
		/// <summary>incoming packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_incoming_packet_ = nullptr;

		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;
		
		/// <summary>map of adapter index to its resources</summary>
		std::unordered_map<size_t, std::unique_ptr<adapter_resources>> adapter_resources_map_;
		
		/// <summary>recursive mutex for thread-safe access to adapter resources map</summary>
		mutable std::recursive_mutex adapter_resources_mutex_;
		
		/// <summary>specifies if sleep should be used on polling fas I/O</summary>
		bool wait_on_poll_{false};
	};

	inline bool multi_fastio_packet_filter::init_filter(size_t adapter_idx)
	{
		if (adapter_idx >= network_interfaces_.size())
			return false;

		std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
		
		auto it = adapter_resources_map_.find(adapter_idx);
		if (it != adapter_resources_map_.end() && it->second->initialized) {
			return true; // Already initialized
		}

		auto resources = std::make_unique<adapter_resources>();
		resources->adapter_index = adapter_idx;
		
		try
		{
			resources->packet_buffer = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);
			resources->write_adapter_request_ptr = std::make_unique<request_storage_type_t>();
			resources->write_mstcp_request_ptr = std::make_unique<request_storage_type_t>();
			resources->fast_io_ptr = std::make_unique<fast_io_storage_type_t[]>(4);
		}
		catch (const std::bad_alloc&)
		{
			return false;
		}

		// Set events for helper driver
		if (wait_on_poll_)
		{
			if (!network_interfaces_[adapter_idx]->set_packet_event())
			{
				return false;
			}
		}

		// 初始化Fast I/O部分
		for (int i = 0; i < 4; ++i)
		{
			void* section_ptr = &(reinterpret_cast<fast_io_storage_type_t*>(resources->fast_io_ptr.get())[i]);
			auto fast_io_section = reinterpret_cast<PFAST_IO_SECTION>(section_ptr);
			
			if (i == 0)
			{
				if (!InitializeFastIo(fast_io_section, static_cast<DWORD>(fast_io_size)))
				{
					return false;
				}
			}
			else
			{
				if (!AddSecondaryFastIo(fast_io_section, static_cast<DWORD>(fast_io_size)))
				{
					return false;
				}
			}
		}

		network_interfaces_[adapter_idx]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);
		resources->initialized = true;
		adapter_resources_map_[adapter_idx] = std::move(resources);
		
		return true;
	}

	inline void multi_fastio_packet_filter::release_filter(size_t adapter_idx)
	{
		std::unique_ptr<adapter_resources> resources_to_release;
		
		{
			std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
			
			auto it = adapter_resources_map_.find(adapter_idx);
			if (it == adapter_resources_map_.end()) {
				return;
			}

			resources_to_release = std::move(it->second);
			adapter_resources_map_.erase(it);
		}
		
		// 现在释放资源，不在锁的保护范围内
		if (adapter_idx < network_interfaces_.size()) {
			network_interfaces_[adapter_idx]->release();
		}
		
		// Change state to stopping and wait for thread
		if (resources_to_release) {
			resources_to_release->state = filter_state::stopping;
			
			if (resources_to_release->working_thread.joinable()) {
				resources_to_release->working_thread.join();
			}
		}
	}

	inline bool multi_fastio_packet_filter::reconfigure()
	{
		std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
		
		// Check if any adapter is currently filtering
		for (const auto& pair : adapter_resources_map_) {
			auto state = pair.second->state.load();
			if (state != filter_state::stopped) {
				return false;
			}
		}

		network_interfaces_.clear();
		adapter_resources_map_.clear();
		
		initialize_network_interfaces();
		
		return true;
	}

	inline bool multi_fastio_packet_filter::start_filter(const size_t adapter)
	{
		std::vector<size_t> adapters = {adapter};
		return start_filters(adapters);
	}

	inline bool multi_fastio_packet_filter::start_filters(const std::vector<size_t>& adapters)
	{
		bool all_started = true;
		
		for (auto adapter : adapters) {
			if (adapter >= network_interfaces_.size()) {
				all_started = false;
				continue;
			}
			
			// 先检查适配器状态
			{
				std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
				auto it = adapter_resources_map_.find(adapter);
				if (it != adapter_resources_map_.end()) {
					auto state = it->second->state.load();
					if (state != filter_state::stopped) {
						all_started = false;
						continue;
					}
				}
			}
			
			// 初始化过滤器（会在内部获取锁）
			if (init_filter(adapter)) {
				std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
				auto it = adapter_resources_map_.find(adapter);
				if (it != adapter_resources_map_.end()) {
					it->second->state = filter_state::starting;
					it->second->working_thread = std::thread(&multi_fastio_packet_filter::filter_working_thread, this, adapter);
				} else {
					all_started = false;
				}
			} else {
				all_started = false;
			}
		}
		
		return all_started;
	}

	inline bool multi_fastio_packet_filter::stop_filter(size_t adapter)
	{
		{
			std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
			
			auto it = adapter_resources_map_.find(adapter);
			if (it == adapter_resources_map_.end()) {
				return false;
			}
			
			auto state = it->second->state.load();
			if (state != filter_state::running && state != filter_state::starting) {
				return false;
			}
		}
		
		release_filter(adapter);
		return true;
	}

	inline bool multi_fastio_packet_filter::stop_all_filters()
	{
		std::vector<size_t> adapters_to_stop;
		
		{
			std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
			for (const auto& pair : adapter_resources_map_) {
				auto state = pair.second->state.load();
				if (state == filter_state::running || state == filter_state::starting) {
					adapters_to_stop.push_back(pair.first);
				}
			}
		}
		
		bool all_stopped = true;
		for (auto adapter : adapters_to_stop) {
			if (!stop_filter(adapter)) {
				all_stopped = false;
			}
		}
		
		return all_stopped;
	}

	inline bool multi_fastio_packet_filter::is_filtering(size_t adapter) const
	{
		std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
		
		auto it = adapter_resources_map_.find(adapter);
		if (it == adapter_resources_map_.end()) {
			return false;
		}
		
		auto state = it->second->state.load();
		return state == filter_state::running;
	}

	inline std::vector<std::string> multi_fastio_packet_filter::get_interface_names_list() const
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline const std::vector<std::unique_ptr<network_adapter>>& multi_fastio_packet_filter::get_interface_list() const
	{
		return network_interfaces_;
	}

	inline void multi_fastio_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		if (!GetTcpipBoundAdaptersInfo(&ad_list))
			return;

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_unique<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data()),
					ad_list.m_nAdapterMediumList[i],
					ad_list.m_usMTU[i]));
		}
	}

	inline multi_fastio_packet_filter::adapter_resources* multi_fastio_packet_filter::get_or_create_adapter_resources(size_t adapter_idx)
	{
		std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
		
		auto it = adapter_resources_map_.find(adapter_idx);
		if (it != adapter_resources_map_.end()) {
			return it->second.get();
		}
		
		return nullptr;
	}

	inline multi_fastio_packet_filter::filter_state multi_fastio_packet_filter::get_filter_state(size_t adapter) const
	{
		std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
		
		auto it = adapter_resources_map_.find(adapter);
		if (it == adapter_resources_map_.end()) {
			return filter_state::stopped;
		}
		
		return it->second->state.load();
	}

	inline std::vector<size_t> multi_fastio_packet_filter::get_filtered_adapters() const
	{
		std::vector<size_t> result;
		std::lock_guard<std::recursive_mutex> lock(adapter_resources_mutex_);
		
		for (const auto& pair : adapter_resources_map_) {
			auto state = pair.second->state.load();
			if (state == filter_state::running) {
				result.push_back(pair.first);
			}
		}
		
		return result;
	}

	inline void multi_fastio_packet_filter::filter_working_thread(size_t adapter_idx)
	{
		using namespace std::chrono_literals;

		auto resources = get_or_create_adapter_resources(adapter_idx);
		if (!resources) {
			return;
		}

		resources->state = filter_state::running;

		DWORD sent_success = 0;
		DWORD fast_io_packets_success = 0;

		auto* const write_adapter_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(resources->write_adapter_request_ptr.get());
		auto* const write_mstcp_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(resources->write_mstcp_request_ptr.get());

		const PFAST_IO_SECTION fast_io_section[] = {
			reinterpret_cast<PFAST_IO_SECTION>(&(reinterpret_cast<fast_io_storage_type_t*>(resources->fast_io_ptr.get())[0])),
			reinterpret_cast<PFAST_IO_SECTION>(&(reinterpret_cast<fast_io_storage_type_t*>(resources->fast_io_ptr.get())[1])),
			reinterpret_cast<PFAST_IO_SECTION>(&(reinterpret_cast<fast_io_storage_type_t*>(resources->fast_io_ptr.get())[2])),
			reinterpret_cast<PFAST_IO_SECTION>(&(reinterpret_cast<fast_io_storage_type_t*>(resources->fast_io_ptr.get())[3])),
		};

		while (resources->state.load() == filter_state::running)
		{
			// Fast I/O processing section
			for (auto i : fast_io_section)
			{
				if (InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0, 0))
				{
					InterlockedExchange(&i->fast_io_header.read_in_progress_flag, 1);

					auto write_union = InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0,
					                                              0);

					auto current_packets_success = reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.
						number_of_packets;

					// Copy packets and reset section
					memmove(&resources->packet_buffer[fast_io_packets_success], &i->fast_io_packets[0],
					        sizeof(INTERMEDIATE_BUFFER) * (current_packets_success - 1));

					// For the last packet(s) wait the write completion if in progress
					write_union = InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0, 0);

					while (reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.write_in_progress_flag)
					{
						write_union = InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0,
						                                         0);
					}

					// Copy the last packet(s)
					memmove(
						&resources->packet_buffer[static_cast<uint64_t>(fast_io_packets_success) + current_packets_success - 1], &
						i->fast_io_packets[current_packets_success - 1], sizeof(INTERMEDIATE_BUFFER));
					if (current_packets_success < reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.
						number_of_packets)
					{
						current_packets_success = reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.
							number_of_packets;
						memmove(
							&resources->packet_buffer[static_cast<uint64_t>(fast_io_packets_success) + current_packets_success - 1], &
							i->fast_io_packets[current_packets_success - 1], sizeof(INTERMEDIATE_BUFFER));
					}

					InterlockedExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0);
					InterlockedExchange(&i->fast_io_header.read_in_progress_flag, 0);

					fast_io_packets_success += current_packets_success;
				}
			}

			auto send_to_adapter_num = 0;
			auto send_to_mstcp_num = 0;

			for (uint32_t i = 0; i < fast_io_packets_success; ++i)
			{
				auto packet_action = packet_action::pass;

				if (resources->packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				{
					if (filter_outgoing_packet_ != nullptr)
						packet_action = filter_outgoing_packet_(resources->packet_buffer[i].m_hAdapter, resources->packet_buffer[i]);
				}
				else
				{
					if (filter_incoming_packet_ != nullptr)
						packet_action = filter_incoming_packet_(resources->packet_buffer[i].m_hAdapter, resources->packet_buffer[i]);
				}

				// Place packet back into the flow if was allowed to
				if (packet_action == packet_action::pass)
				{
					if (resources->packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						write_adapter_request[send_to_adapter_num] = &resources->packet_buffer[i];
						++send_to_adapter_num;
					}
					else
					{
						write_mstcp_request[send_to_mstcp_num] = &resources->packet_buffer[i];
						++send_to_mstcp_num;
					}
				}
				else if (packet_action == packet_action::revert)
				{
					if (resources->packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
					{
						write_adapter_request[send_to_adapter_num] = &resources->packet_buffer[i];
						++send_to_adapter_num;
					}
					else
					{
						write_mstcp_request[send_to_mstcp_num] = &resources->packet_buffer[i];
						++send_to_mstcp_num;
					}
				}
			}

			if (send_to_adapter_num > 0)
			{
				SendPacketsToAdaptersUnsorted(write_adapter_request, send_to_adapter_num, &sent_success);
			}

			if (send_to_mstcp_num > 0)
			{
				SendPacketsToMstcpUnsorted(write_mstcp_request, send_to_mstcp_num, &sent_success);
			}

			if (fast_io_packets_success == 0 && wait_on_poll_ && adapter_idx < network_interfaces_.size())
			{
				auto [[maybe_unused]] result = network_interfaces_[adapter_idx]->wait_event(INFINITE);
				result = network_interfaces_[adapter_idx]->reset_event();
			}

			fast_io_packets_success = 0;
		}
		
		resources->state = filter_state::stopped;
	}
}