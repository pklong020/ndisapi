// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  multi_packet_filter.h 
/// Abstract: Multi-interface packet filter class
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

namespace ndisapi
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Multi-interface winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class multi_packet_filter final : public CNdisApi
	{
	public:
		/// <summary>
		/// Defines packet action
		/// </summary>
		enum class packet_action
		{
			/// <summary>
			/// pass the packet over
			/// </summary>
			pass,
			/// <summary>
			/// drop the packet
			/// </summary>
			drop,
			/// <summary>
			/// change packet direction (e.g. forward incoming packet out)
			/// </summary>
			revert,
			/// <summary>
			/// forward packet via another network interface
			/// </summary>
			route,
			/// <summary>
			/// forward packet via another network interface and change its direction
			/// </summary>
			route_revert
		};

	private:
		/// <summary>
		/// Defines maximum number of network packets to read via one I/O operation
		/// </summary>
		static constexpr size_t maximum_packet_block = 510;

		/// <summary>
		/// Storage type for the I/O operations
		/// </summary>
		using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
		                                                      sizeof(NDISRD_ETH_Packet) * (maximum_packet_block - 1),
		                                                      0x1000>;

		/// <summary>
		/// Defines current NDIS filtering state
		/// </summary>
		enum class filter_state
		{
			stopped,
			starting,
			running,
			stopping
		};

		/// <summary>
		/// Constructor
		/// </summary>
		multi_packet_filter():
			adapter_event_(CreateEvent(nullptr, TRUE, FALSE, nullptr))
		{
			SetAdapterListChangeEvent(static_cast<HANDLE>(adapter_event_));
			initialize_network_interfaces();

			adapter_watch_thread_ = std::thread([this]()
			{
				while (!adapter_watch_exit_.load())
				{
					[[maybe_unused]] auto wait_result = adapter_event_.wait(INFINITE);
					[[maybe_unused]] auto reset_result = adapter_event_.reset_event();

					if (adapter_watch_exit_.load())
						return;

					update_network_interfaces();

					// 通知所有回调
					{
						std::lock_guard<std::mutex> lock(callback_mutex_);
						for (auto& callback : adapters_change_callback_)
						{
							if (callback != nullptr)
							{
								callback();
							}
						}
					}
				}
			});
		}

	public:
		// ********************************************************************************
		/// <summary>
		/// Destructor: stops filtering and releases resources
		/// </summary>
		~multi_packet_filter() override
		{
			adapter_watch_exit_.store(true);
			[[maybe_unused]] auto signal_result = adapter_event_.signal();
			
			stop_all_filters();

			if (adapter_watch_thread_.joinable())
				adapter_watch_thread_.join();
		}

		/// <summary>
		/// Deleted copy constructor
		/// </summary>
		multi_packet_filter(const multi_packet_filter& other) = delete;
		/// <summary>
		/// Deleted move constructor
		/// </summary>
		multi_packet_filter(multi_packet_filter&& other) noexcept = delete;
		/// <summary>
		/// Deleted copy assignment
		/// </summary>
		multi_packet_filter& operator=(const multi_packet_filter& other) = delete;
		/// <summary>
		/// Deleted move assignment
		/// </summary>
		multi_packet_filter& operator=(multi_packet_filter&& other) noexcept = delete;

		// ********************************************************************************
		/// <summary>
		/// Constructs multi_packet_filter with packet handlers
		/// </summary>
		/// <param name="default_in">default incoming packets handling routine</param>
		/// <param name="default_out">default outgoing packet handling routine</param>
		/// <returns></returns>
		// ********************************************************************************
		template <typename F1, typename F2>
		multi_packet_filter(F1 default_in, F2 default_out) : multi_packet_filter()
		{
			default_filter_incoming_packet_ = default_in;
			default_filter_outgoing_packet_ = default_out;
		}

		// ********************************************************************************
		/// <summary>
		/// Updates available network interfaces.
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool reconfigure();

		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering on specified adapter
		/// </summary>
		/// <param name="adapter_index">adapter index in network_interfaces_</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filter(size_t adapter_index);

		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering on multiple adapters
		/// </summary>
		/// <param name="adapter_indices">vector of adapter indices to filter</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filters(const std::vector<size_t>& adapter_indices);
		
		// ********************************************************************************
		/// <summary>
		/// Stops packet filtering on specified adapter
		/// </summary>
		/// <param name="adapter_index">adapter index to stop</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool stop_filter(size_t adapter_index);
		
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
		/// <param name="adapter_index">adapter index to check</param>
		/// <returns>true if filtering, false otherwise</returns>
		// ********************************************************************************
		bool is_filtering(size_t adapter_index) const;

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
		const std::vector<std::shared_ptr<network_adapter>>& get_interface_list() const;

		// ********************************************************************************
		/// <summary>
		/// Resets adapter filter mode for the specified network interface
		/// </summary>
		/// <param name="adapter">adapter handle to reset</param>
		/// <returns>boolean result of the operation</returns>
		// ********************************************************************************
		bool reset_adapter_mode(HANDLE adapter) const
		{
			ADAPTER_MODE mode = {adapter, 0};
			return SetAdapterMode(&mode);
		}

		// ********************************************************************************
		/// <summary>
		/// Checks if adapter is in non-default filter mode for the specified network interface
		/// </summary>
		/// <param name="adapter">adapter handle </param>
		/// <returns>false if adapter is in filter mode, true otherwise</returns>
		// ********************************************************************************
		bool is_default_adapter_mode(HANDLE adapter) const
		{
			ADAPTER_MODE mode = {adapter, 0};
			if (GetAdapterMode(&mode))
			{
				return (mode.dwFlags == 0);
			}

			return true;
		}

		// ********************************************************************************
		/// <summary>
		/// Registers adapter change callback
		/// </summary>
		/// <param name="callback">callback function</param>
		/// <returns>true if successful, false otherwise</returns>
		// ********************************************************************************
		bool register_adapters_callback(std::function<void()> callback)
		{
			try
			{
				std::lock_guard<std::mutex> lock(callback_mutex_);
				adapters_change_callback_.emplace_back(std::move(callback));
			}
			catch (...)
			{
				return false;
			}

			return true;
		}

		// ********************************************************************************
		/// <summary>
		/// Updates available network interface list
		/// </summary>
		// ********************************************************************************
		bool update_network_interfaces();

	private:
		// ********************************************************************************
		/// <summary>
		/// Working thread routine for specific adapter
		/// </summary>
		/// <param name="adapter_idx">adapter index in network_interfaces_</param>
		/// <param name="adapter">network_adapter class instance</param>
		// ********************************************************************************
		void filter_working_thread(size_t adapter_idx, std::shared_ptr<network_adapter> adapter);

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
		/// <param name="adapter_idx">adapter index in network_interfaces_</param>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool init_filter(size_t adapter_idx);

		// ********************************************************************************
		/// <summary>
		/// Release interface and associated data structures required for packet filtering
		/// </summary>
		/// <param name="adapter_idx">adapter index in network_interfaces_</param>
		// ********************************************************************************
		void release_filter(size_t adapter_idx);

		/// <summary>adapter list monitoring event</summary>
		std::thread adapter_watch_thread_;
		/// <summary>adapter list exit flag</summary>
		std::atomic_bool adapter_watch_exit_{false};
		/// <summary>adapter list monitoring event</summary>
		winsys::safe_event adapter_event_;
		
		/// <summary>default packet handlers</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> default_filter_outgoing_packet_ = nullptr;
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> default_filter_incoming_packet_ = nullptr;
		
		/// <summary>list of available network interfaces</summary>
		std::vector<std::shared_ptr<network_adapter>> network_interfaces_{};
		
		/// <summary>working thread running status (使用unique_ptr避免atomic拷贝问题)</summary>
		std::vector<std::unique_ptr<std::atomic<filter_state>>> filter_states_{};
		
		/// <summary>working thread objects</summary>
		std::vector<std::thread> working_threads_{};
		
		/// <summary>array of INTERMEDIATE_BUFFER structures per adapter</summary>
		std::vector<std::unique_ptr<INTERMEDIATE_BUFFER[]>> packet_buffers_{};
		
		/// <summary>driver request for reading packets per adapter</summary>
		std::vector<std::unique_ptr<request_storage_type_t>> read_request_ptrs_{};
		
		/// <summary>driver request for writing packets to adapter per adapter</summary>
		std::vector<std::unique_ptr<request_storage_type_t>> write_adapter_request_ptrs_{};
		
		/// <summary>driver request for writing packets up to protocol stack per adapter</summary>
		std::vector<std::unique_ptr<request_storage_type_t>> write_mstcp_request_ptrs_{};
		
		/// <summary>callback mutex</summary>
		std::mutex callback_mutex_;
		
		/// <summary>callback to notify for adapters changes</summary>
		std::vector<std::function<void()>> adapters_change_callback_{};
	};

	inline bool multi_packet_filter::init_filter(const size_t adapter_idx)
	{
		if (adapter_idx >= network_interfaces_.size())
			return false;

		// 分配存储空间（如果尚未分配）
		if (adapter_idx >= packet_buffers_.size()) {
			packet_buffers_.resize(adapter_idx + 1);
			read_request_ptrs_.resize(adapter_idx + 1);
			write_adapter_request_ptrs_.resize(adapter_idx + 1);
			write_mstcp_request_ptrs_.resize(adapter_idx + 1);
		}

		// 如果已经分配，检查是否已经初始化
		if (packet_buffers_[adapter_idx] != nullptr) {
			return true;
		}

		try
		{
			packet_buffers_[adapter_idx] = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);
			read_request_ptrs_[adapter_idx] = std::make_unique<request_storage_type_t>();
			write_adapter_request_ptrs_[adapter_idx] = std::make_unique<request_storage_type_t>();
			write_mstcp_request_ptrs_[adapter_idx] = std::make_unique<request_storage_type_t>();
		}
		catch (const std::bad_alloc&)
		{
			return false;
		}

		auto* read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptrs_[adapter_idx].get());
		auto* write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptrs_[adapter_idx].get());
		auto* write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptrs_[adapter_idx].get());

		read_request->hAdapterHandle = network_interfaces_[adapter_idx]->get_adapter();
		write_adapter_request->hAdapterHandle = network_interfaces_[adapter_idx]->get_adapter();
		write_mstcp_request->hAdapterHandle = network_interfaces_[adapter_idx]->get_adapter();

		read_request->dwPacketsNumber = maximum_packet_block;
		write_adapter_request->dwPacketsNumber = 0;
		write_mstcp_request->dwPacketsNumber = 0;

		// Initialize packet buffers
		ZeroMemory(packet_buffers_[adapter_idx].get(), sizeof(INTERMEDIATE_BUFFER) * maximum_packet_block);

		for (unsigned i = 0; i < maximum_packet_block; ++i)
		{
			read_request->EthPacket[i].Buffer = &packet_buffers_[adapter_idx][i];
		}

		// Set events for helper driver
		if (!network_interfaces_[adapter_idx]->set_packet_event())
		{
			return false;
		}

		network_interfaces_[adapter_idx]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

		return true;
	}

	inline void multi_packet_filter::release_filter(const size_t adapter_idx)
	{
		if (adapter_idx >= network_interfaces_.size())
			return;

		network_interfaces_[adapter_idx]->release();

		// Wait for working thread to exit
		if (adapter_idx < working_threads_.size() && working_threads_[adapter_idx].joinable())
			working_threads_[adapter_idx].join();

		// Release resources
		if (adapter_idx < packet_buffers_.size()) {
			packet_buffers_[adapter_idx].reset();
			read_request_ptrs_[adapter_idx].reset();
			write_adapter_request_ptrs_[adapter_idx].reset();
			write_mstcp_request_ptrs_[adapter_idx].reset();
		}
	}

	inline bool multi_packet_filter::reconfigure()
	{
		return update_network_interfaces();
	}

	inline bool multi_packet_filter::start_filter(const size_t adapter_idx)
	{
		if (adapter_idx >= network_interfaces_.size())
			return false;

		// 确保状态向量足够大
		if (adapter_idx >= filter_states_.size()) {
			filter_states_.resize(adapter_idx + 1);
		}

		// 初始化状态（如果尚未初始化）
		if (!filter_states_[adapter_idx]) {
			filter_states_[adapter_idx] = std::make_unique<std::atomic<filter_state>>(filter_state::stopped);
		}

		if (filter_states_[adapter_idx]->load() == filter_state::running)
			return true;

		if (!init_filter(adapter_idx))
			return false;

		try
		{
			// 确保线程向量足够大
			if (adapter_idx >= working_threads_.size()) {
				working_threads_.resize(adapter_idx + 1);
			}
			
			filter_states_[adapter_idx]->store(filter_state::starting);
			working_threads_[adapter_idx] = std::thread(&multi_packet_filter::filter_working_thread, this,
			                                            adapter_idx, network_interfaces_[adapter_idx]);
		}
		catch (...)
		{
			filter_states_[adapter_idx]->store(filter_state::stopped);
			return false;
		}

		return true;
	}

	inline bool multi_packet_filter::start_filters(const std::vector<size_t>& adapter_indices)
	{
		bool all_started = true;
		
		for (auto idx : adapter_indices) {
			if (!start_filter(idx)) {
				all_started = false;
			}
		}
		
		return all_started;
	}

	inline bool multi_packet_filter::stop_filter(const size_t adapter_idx)
	{
		if (adapter_idx >= filter_states_.size() || 
			!filter_states_[adapter_idx] ||
			filter_states_[adapter_idx]->load() == filter_state::stopped)
			return true;

		filter_states_[adapter_idx]->store(filter_state::stopping);

		release_filter(adapter_idx);

		if (adapter_idx < filter_states_.size() && filter_states_[adapter_idx]) {
			filter_states_[adapter_idx]->store(filter_state::stopped);
		}

		return true;
	}

	inline bool multi_packet_filter::stop_all_filters()
	{
		bool all_stopped = true;
		
		for (size_t i = 0; i < filter_states_.size(); ++i) {
			if (filter_states_[i] && filter_states_[i]->load() == filter_state::running) {
				if (!stop_filter(i)) {
					all_stopped = false;
				}
			}
		}
		
		return all_stopped;
	}

	inline bool multi_packet_filter::is_filtering(const size_t adapter_idx) const
	{
		if (adapter_idx >= filter_states_.size() || !filter_states_[adapter_idx])
			return false;
			
		return filter_states_[adapter_idx]->load() == filter_state::running;
	}

	inline std::vector<std::string> multi_packet_filter::get_interface_names_list() const
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline const std::vector<std::shared_ptr<network_adapter>>& multi_packet_filter::get_interface_list() const
	{
		return network_interfaces_;
	}

	inline void multi_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		GetTcpipBoundAdaptersInfo(&ad_list);

		network_interfaces_.clear();
		filter_states_.clear();
		working_threads_.clear();
		packet_buffers_.clear();
		read_request_ptrs_.clear();
		write_adapter_request_ptrs_.clear();
		write_mstcp_request_ptrs_.clear();

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_shared<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data()),
					ad_list.m_nAdapterMediumList[i],
					ad_list.m_usMTU[i]));
		}
	}

	inline bool multi_packet_filter::update_network_interfaces()
	{
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		if (!GetTcpipBoundAdaptersInfo(&ad_list))
			return false;

		// 停止所有正在运行的过滤器
		stop_all_filters();

		network_interfaces_.clear();

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_shared<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data()),
					ad_list.m_nAdapterMediumList[i],
					ad_list.m_usMTU[i]));
		}

		// 重置状态
		filter_states_.clear();
		working_threads_.clear();
		packet_buffers_.clear();
		read_request_ptrs_.clear();
		write_adapter_request_ptrs_.clear();
		write_mstcp_request_ptrs_.clear();

		return true;
	}

	inline void multi_packet_filter::filter_working_thread(const size_t adapter_idx, std::shared_ptr<network_adapter> adapter)
	{
		if (adapter_idx >= packet_buffers_.size() || 
			adapter_idx >= read_request_ptrs_.size() ||
			adapter_idx >= write_adapter_request_ptrs_.size() ||
			adapter_idx >= write_mstcp_request_ptrs_.size() ||
			adapter_idx >= filter_states_.size() ||
			!filter_states_[adapter_idx])
			return;

		auto* read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptrs_[adapter_idx].get());
		auto* write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptrs_[adapter_idx].get());
		auto* write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptrs_[adapter_idx].get());

		filter_states_[adapter_idx]->store(filter_state::running);

		while (filter_states_[adapter_idx]->load() == filter_state::running)
		{
			[[maybe_unused]] auto wait_result = adapter->wait_event(INFINITE);
			[[maybe_unused]] auto reset_result = adapter->reset_event();

			while (filter_states_[adapter_idx]->load() == filter_state::running && ReadPackets(read_request))
			{
				for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
				{
					auto packet_action = multi_packet_filter::packet_action::pass;

					if (packet_buffers_[adapter_idx][i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						if (default_filter_outgoing_packet_ != nullptr)
							packet_action = default_filter_outgoing_packet_(
								read_request->hAdapterHandle, packet_buffers_[adapter_idx][i]);
					}
					else
					{
						if (default_filter_incoming_packet_ != nullptr)
							packet_action = default_filter_incoming_packet_(
								read_request->hAdapterHandle, packet_buffers_[adapter_idx][i]);
					}

					// Place packet back into the flow if was allowed to
					switch (packet_action)
					{
					case packet_action::pass:
						if (packet_buffers_[adapter_idx][i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &
								packet_buffers_[adapter_idx][i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &
								packet_buffers_[adapter_idx][i];
							++write_mstcp_request->dwPacketsNumber;
						}
						break;
					case packet_action::revert:
						if (packet_buffers_[adapter_idx][i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &
								packet_buffers_[adapter_idx][i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &
								packet_buffers_[adapter_idx][i];
							++write_mstcp_request->dwPacketsNumber;
						}
						break;
					case packet_action::drop:
						break;
					default:
						// route和route_revert在这个简单版本中不实现
						break;
					}
				}

				if (write_adapter_request->dwPacketsNumber)
				{
					SendPacketsToAdapter(write_adapter_request);
					write_adapter_request->dwPacketsNumber = 0;
				}

				if (write_mstcp_request->dwPacketsNumber)
				{
					SendPacketsToMstcp(write_mstcp_request);
					write_mstcp_request->dwPacketsNumber = 0;
				}

				read_request->dwPacketsSuccess = 0;
			}
		}
		
		filter_states_[adapter_idx]->store(filter_state::stopped);
	}
}