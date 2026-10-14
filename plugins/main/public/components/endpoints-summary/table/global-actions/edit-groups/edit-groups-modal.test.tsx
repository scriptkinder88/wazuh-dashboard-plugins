import React from 'react';
import { render, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import { useGetGroups } from '../../../hooks';
import { addAgentsToGroupService, createGroupService } from '../../../services';
import { EditAgentsGroupsModal } from './edit-groups-modal';
import { Agent } from '../../../types';

jest.mock('../../../services', () => ({
  addAgentsToGroupService: jest.fn(),
  createGroupService: jest.fn(),
  getAgentsService: jest.fn(),
  groupNameError: jest.requireActual('../../../services/group-name')
    .groupNameError,
  removeAgentsFromGroupService: jest.fn(),
}));

jest.mock('../../../hooks', () => ({
  useGetGroups: jest.fn(),
}));

jest.mock('../../../../../react-services/common-services', () => ({
  getErrorOrchestrator: () => ({
    handleError: () => {},
  }),
}));

// the jest.mock of @osd/monaco is added due to a problem transcribing the files to run the tests.
// https://github.com/wazuh/wazuh-dashboard-plugins/pull/6921#issuecomment-2298289550

jest.mock('@osd/monaco', () => ({
  monaco: {},
}));

describe('EditAgentsGroupsModal component', () => {
  test('should return the component with save disabled', async () => {
    (useGetGroups as jest.Mock).mockReturnValue({
      isLoading: true,
    });

    const { container, getByText, getByRole } = render(
      <EditAgentsGroupsModal
        selectedAgents={[
          {
            id: '001',
            name: 'agent1',
            group: ['default'],
          } as Agent,
        ]}
        allAgentsSelected={false}
        filters={{}}
        onClose={() => {}}
        reloadAgents={() => {}}
        addOrRemove='add'
      />,
    );

    expect(container).toMatchSnapshot();

    const agentCount = getByText('1');
    expect(agentCount).toBeInTheDocument();

    const saveButton = getByRole('button', { name: 'Save' });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton).toBeDisabled();

    const cancelButton = getByRole('button', { name: 'Cancel' });
    expect(cancelButton).toBeInTheDocument();
  });

  test('should select a new group', async () => {
    (useGetGroups as jest.Mock).mockReturnValue({
      isLoading: false,
      groups: ['default', 'group1', 'group2'],
    });

    const { getByText, getAllByText, getByRole } = render(
      <EditAgentsGroupsModal
        selectedAgents={[
          {
            id: '001',
            name: 'agent1',
            group: ['default'],
          } as Agent,
        ]}
        allAgentsSelected={false}
        filters={{}}
        onClose={() => {}}
        reloadAgents={() => {}}
        addOrRemove='add'
      />,
    );

    const saveButton = getByRole('button', { name: 'Save' });
    expect(saveButton).toBeInTheDocument();

    const select = getAllByText('Select groups to add')[0];
    expect(select).toBeInTheDocument();

    act(() => {
      fireEvent.click(select);
    });

    await waitFor(() => expect(getByText('group1')).toBeInTheDocument());

    act(() => {
      fireEvent.click(getByText('group1'));
      fireEvent.click(saveButton);
    });
  });

  const renderAddModal = () =>
    render(
      <EditAgentsGroupsModal
        selectedAgents={[
          { id: '001', name: 'agent1', group: ['default'] } as Agent,
        ]}
        allAgentsSelected={false}
        filters={{}}
        onClose={() => {}}
        reloadAgents={() => {}}
        addOrRemove='add'
      />,
    );

  const typeGroup = (name: string) => {
    const input = document.querySelector(
      '[data-test-subj="comboBoxSearchInput"]',
    ) as HTMLInputElement;
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: name } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
  };

  test('should create a new group and add the agents to it', async () => {
    (createGroupService as jest.Mock).mockClear();
    (addAgentsToGroupService as jest.Mock).mockClear();
    (useGetGroups as jest.Mock).mockReturnValue({
      isLoading: false,
      groups: ['default'],
    });
    (createGroupService as jest.Mock).mockResolvedValue({ data: { error: 0 } });
    (addAgentsToGroupService as jest.Mock).mockResolvedValue({
      data: {
        /* eslint-disable camelcase */
        data: {
          affected_items: ['001'],
          failed_items: [],
          total_failed_items: 0,
        },
        /* eslint-enable camelcase */
        error: 0,
        message: 'All selected agents were assigned',
      },
    });

    const { getByRole, getByText } = renderAddModal();
    expect(
      getByText('To create a new group, type its name and press Enter'),
    ).toBeInTheDocument();
    typeGroup('web-prod');
    expect(getByText('web-prod')).toBeInTheDocument();

    fireEvent.click(getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(addAgentsToGroupService).toHaveBeenCalledWith({
        agentIds: ['001'],
        groupId: 'web-prod',
      }),
    );
    expect(createGroupService).toHaveBeenCalledWith('web-prod');
    expect(
      (createGroupService as jest.Mock).mock.invocationCallOrder[0],
    ).toBeLessThan(
      (addAgentsToGroupService as jest.Mock).mock.invocationCallOrder[0],
    );
  });

  test('should create a group typed twice only once', async () => {
    (useGetGroups as jest.Mock).mockReturnValue({
      isLoading: false,
      groups: ['default'],
    });
    (createGroupService as jest.Mock)
      .mockClear()
      .mockResolvedValue({ data: { error: 0 } });
    (addAgentsToGroupService as jest.Mock).mockClear().mockResolvedValue({
      data: {
        /* eslint-disable camelcase */
        data: {
          affected_items: ['001'],
          failed_items: [],
          total_failed_items: 0,
        },
        /* eslint-enable camelcase */
        error: 0,
        message: 'All selected agents were assigned',
      },
    });

    const { getByRole, baseElement } = renderAddModal();
    typeGroup('web-prod');
    typeGroup('web-prod');
    const selected = Array.from(
      baseElement.querySelectorAll('.euiBadge__text'),
    ).filter(badge => badge.textContent === 'web-prod');
    expect(selected).toHaveLength(1);

    fireEvent.click(getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(addAgentsToGroupService).toHaveBeenCalled());
    expect(createGroupService).toHaveBeenCalledTimes(1);
    expect(addAgentsToGroupService).toHaveBeenCalledTimes(1);
  });

  test('should refuse an invalid or existing group name', () => {
    (useGetGroups as jest.Mock).mockReturnValue({
      isLoading: false,
      groups: ['default'],
    });
    (createGroupService as jest.Mock).mockClear();

    const { getByRole, getByText } = renderAddModal();
    typeGroup('web prod');
    expect(
      getByText('Use only letters, numbers, "_", "-" and "."'),
    ).toBeInTheDocument();
    expect(getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(createGroupService).not.toHaveBeenCalled();
  });

  test('should not add the agents when the group cannot be created', async () => {
    (useGetGroups as jest.Mock).mockReturnValue({
      isLoading: false,
      groups: ['default'],
    });
    (createGroupService as jest.Mock).mockRejectedValue(
      new Error('permission denied'),
    );
    (addAgentsToGroupService as jest.Mock).mockClear();

    const { getByRole } = renderAddModal();
    typeGroup('web-prod');
    fireEvent.click(getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(createGroupService).toHaveBeenCalledWith('web-prod'),
    );
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(addAgentsToGroupService).not.toHaveBeenCalled();
  });
});
